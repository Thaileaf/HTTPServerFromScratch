
import http from 'k6/http';
import { sleep } from 'k6';
// import { htmlReport } from "https://raw.githubusercontent.com/benc-uk/k6-reporter/main/dist/bundle.js";

export const options = {
//   vus: 10,
//   duration: '30s',
    scenarios: {
        smoke: {
            executor: 'constant-vus',
            vus: 1,
            duration: '30s',
            tags: { test_type: "smoke" },
        },
        stress: {
            executor: 'ramping-vus',
            startTime: '35s',
            stages: [ 
                { duration: '30s', target: 10000 }, // Ramp up to 2000 users and then back down
                // { duration: '30s', target: 2000 },
                // { duration: '30m', target: 0 },
            ],
            tags: { test_type: "stress" }
        },
    },
    thresholds: {
        http_req_failed: [
            {
                threshold: 'rate<.01',
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
};

export default function () {
    
  http.get('http://localhost:8080');
  sleep(1);
}

// export function handleSummary(data) {
//   return {
//     "summary.html": htmlReport(data),
//   };
// }