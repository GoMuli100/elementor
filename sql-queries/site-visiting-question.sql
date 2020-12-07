SELECT site,
    SUM(case 
            when pd.site is not null then number_of_visitors 
            else 0 end
        ) *100/SUM(number_of_visitors) as promotionVisitsPct
FROM site_visitors sv
    LEFT JOIN promotion_dates pd ON sv.site=pd.site and sv.date>=pd.start_date and sv.date<=pd.end_date
GROUP BY sv.site