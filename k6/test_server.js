import http from 'k6/http';
import { sleep, check } from 'k6';

// Define options for your test
// export const options = {
//   // A simple scenario: 10 Virtual Users (VUs) for 30 seconds
//   vus: 10,
//   duration: '30s',

//   // Or, define stages for a more realistic ramp-up/ramp-down
//   // stages: [
//   //   { duration: '1m', target: 50 },  // Ramp up to 50 VUs in 1 minute
//   //   { duration: '3m', target: 50 },  // Stay at 50 VUs for 3 minutes
//   //   { duration: '1m', target: 0 },   // Ramp down to 0 VUs in 1 minute
//   // ],

//   // Define thresholds to assert performance goals
//   // If any threshold fails, the test run will exit with a non-zero status code
//   thresholds: {
//     http_req_duration: ['p(95)<200'], // 95% of requests must complete within 200ms
//     'http_req_failed{status:400}': ['rate<0.01'], // Less than 1% of requests should have a 400 status
//     'http_req_failed{status:500}': ['rate<0.001'], // Less than 0.1% of requests should have a 500 status
//     checks: ['rate>0.99'], // 99% of checks must pass
//   },
// };

// This is the default function that Virtual Users will execute repeatedly
export default function () {
  // Replace with the URL of your custom HTTP server
  const res = http.get('http://localhost:8080/'); 

  // Basic check: verify that the response status is 200 OK
//   check(res, {
//     'is status 200': (r) => r.status === 200,
//   });

  // Simulate user thinking time or processing time
  // This is important for realistic load patterns
  sleep(1); // Wait for 1 second between requests
}