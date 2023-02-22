/*
 *     Copyright 2022 The Dragonfly Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package types

const (
	ActiveDeadlineSeconds = 60 * 60 * 24 * 7
	TokenExpireTime       = 60 * 60 * 12
	OffsetFrom            = 0
	OffsetTo              = 1000

	AuthRespHeader = "X-Subject-Token"
	AuthHeader     = "X-auth-Token"

	HengQinUrl  = "http://paas.120-236-247-203.nip.io:30088"
	NamespaceId = "44451b0c47cc421986261325d4693174"
)

const (
	// AffinitySeparator is separator of affinity.
	AffinitySeparator = "|"
)
