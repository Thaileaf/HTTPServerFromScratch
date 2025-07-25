import http from 'k6/http';
import { htmlReport } from "https://raw.githubusercontent.com/benc-uk/k6-reporter/main/dist/bundle.js";

export const options = {
    // Thresholds must be a top-level property of options
    thresholds: {
        http_req_failed: [
            {
                threshold: 'rate<.05',
                abortOnFail: true,
                delayAbortEval: '10s',
            },
            
        ],
        http_req_duration: [{
            threshold: 'p(95)<200',
            abortOnFail: true,
            delayAbortEval: '10s'
        }], // 95% of requests should be below 200ms
    },

    scenarios: {
        breakpoint: {
            executor: 'ramping-arrival-rate',
            timeUnit: '1s',
            preAllocatedVUs: 50,
            maxVUs: 2000, 
            stages: [
                { duration: '30s', target: 10000 },
            ],
        },
    },
};

export default function () {
  http.get('http://localhost:8080');
}

export function handleSummary(data) {
  return {
    "summary_breakpoint.html": htmlReport(data),
  };
}