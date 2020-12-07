/* OPTION 1 WITH WINDOWS FUNCTIONS */
;WITH CTE
AS
(
	SELECT department_id, salary, 
        LAG(salary) OVER (PARTITION BY department_id ORDER BY salary desc) as nextSal,
        ROW_NUMBER() OVER (PARTITION BY department_id ORDER BY salary desc) as rid
    FROM employees
)
SELECT department_name, salary as maxSal, salary-nextSal as diffSal
FROM departments d
    INNER JOIN CTE ON CTE.department_id=d.department_id
WHERE CTE.rid=1

/* OPTION 1 WITHOUT WINDOWS FUNCTIONS */
;WITH CTE
AS
(
    SELECT department_id,MAX(salary) as maxSal
    FROM employees
    GROUP BY department_id
),
CTE2 AS
(
    SELECT department_id,MAX(salary) as nextMaxSal
    FROM employees e
        JOIN CTE ON CTE.department_id=e.department_id and CTE.maxSal>e.salary
    GROUP BY e.department_id
)
SELECT department_name, maxSal, maxSal-nextMaxSal as diffSal
FROM departments d
    INNER JOIN CTE ON CTE.department_id=d.department_id
    INNER JOIN CTE2 ON CTE2.department_id=d.department_id