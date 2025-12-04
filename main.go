package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	"github.com/aws/aws-sdk-go-v2/service/inspector2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/olekukonko/tablewriter"
)

func checkCallerIdentity(ctx context.Context, config aws.Config) error {
	client := sts.NewFromConfig(config)
	identity, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return err
	}
	fmt.Printf("Account: %s, Arn: %s\n", aws.ToString(identity.Account), aws.ToString(identity.Arn))
	return nil
}

func stringPtr(s string) *string {
	return &s
}

func fetchFindings(ctx context.Context, config aws.Config, tag *string, ignore *string) ([]types.Finding, error) {
	filerCriteria :=
		&types.FilterCriteria{
			EcrImageTags: []types.StringFilter{{
				Comparison: types.StringComparisonEquals,
				Value:      tag,
			}},
		}
	if ignore != nil && *ignore != "" {
		ignoredRepos := strings.SplitSeq(*ignore, ",")
		for r := range ignoredRepos {
			filerCriteria.EcrImageRepositoryName = append(filerCriteria.EcrImageRepositoryName,
				types.StringFilter{
					Comparison: types.StringComparisonNotEquals,
					Value:      stringPtr(r),
				},
			)
		}
	}
	client := inspector2.NewFromConfig(config)
	fmt.Println("Getting findings ...")
	listResult, err := client.ListFindings(ctx, &inspector2.ListFindingsInput{
		FilterCriteria: filerCriteria,
	})
	if err != nil {
		return nil, err
	}
	findings := listResult.Findings
	for listResult.NextToken != nil {
		fmt.Println("Getting further findings ...")
		listResult, err = client.ListFindings(ctx, &inspector2.ListFindingsInput{
			// Resubmit filer criteria otherwise a validation error occurs
			FilterCriteria: filerCriteria,
			NextToken:      listResult.NextToken,
		})
		if err != nil {
			return findings, err
		}
		findings = append(findings, listResult.Findings...)
	}
	return findings, err
}

func extractRepo(f types.Finding) string {
	if len(f.Resources) != 1 {
		fmt.Println("Unexpected number of resources")
		return ""
	}
	if f.Resources[0].Details.AwsEcrContainerImage == nil {
		fmt.Println("Missing ECR details")
		return ""
	}
	name := f.Resources[0].Details.AwsEcrContainerImage.RepositoryName
	if name == nil {
		fmt.Println("No name")
		return ""
	}
	return *name
}

type summary struct {
	critical int
	high     int
	medium   int
	low      int
}

func (s summary) total() int {
	return s.critical + s.high + s.medium + s.low
}

func main() {
	ctx := context.Background()

	// Program flags
	profile := flag.String("p", "", "Name of AWS profile")
	tag := flag.String("t", "", "Image tag used for filtering")
	ignore := flag.String("i", "", "Repositories to ignore")
	flag.Parse()

	if *profile == "" {
		log.Fatal("Please provide a AWS profile name")
	}
	if *tag == "" {
		log.Fatal("Please provide an image tag")
	}

	// Create AWS config
	config, err := config.LoadDefaultConfig(ctx, config.WithSharedConfigProfile(*profile))
	if err != nil {
		log.Fatal(err)
	}

	err = checkCallerIdentity(ctx, config)
	if err != nil {
		log.Fatal(err)
	}

	// Fetch findings
	findings, err := fetchFindings(ctx, config, tag, ignore)
	if err != nil {
		log.Fatal(err)
	}

	// Summary Table
	summaryTable := make(map[string]summary)
	var totals summary
	for _, f := range findings {
		name := extractRepo(f)
		if name == "" {
			continue
		}
		s := summaryTable[name]
		switch f.Severity {
		case types.SeverityCritical:
			s.critical += 1
			totals.critical += 1
		case types.SeverityHigh:
			s.high += 1
			totals.high += 1
		case types.SeverityMedium:
			s.medium += 1
			totals.medium += 1
		case types.SeverityLow:
			s.low += 1
			totals.low += 1
		}
		summaryTable[name] = s
	}

	// Get all repo names
	var repoNames []string
	for k := range summaryTable {
		repoNames = append(repoNames, k)
	}
	// Sort keys
	sort.Strings(repoNames)

	// Create and render
	table := tablewriter.NewWriter(os.Stdout)
	table.Header([]string{"Repository", "Tag", "Critical", "High", "Medium", "Low", "Total"})
	for _, n := range repoNames {
		s := summaryTable[n]
		table.Append([]any{n, *tag, s.critical, s.high, s.medium, s.low, s.total()})
	}
	table.Footer("Total", "", totals.critical, totals.high, totals.medium, totals.low, totals.total())

	table.Render()
}
