
rule Trojan_BAT_Ader_EC_MTB{
	meta:
		description = "Trojan:BAT/Ader.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {63 6e 56 75 59 58 4d 3d 3c 49 43 31 44 62 32 31 74 59 57 35 6b 49 45 46 6b 5a 43 31 4e 63 46 42 79 5a 57 5a 6c 63 6d 56 75 59 32 55 67 4c 55 56 34 59 32 78 31 63 32 6c 76 62 6c 42 68 64 47 67 67 4a 77 3d 3d } //1 cnVuYXM=<IC1Db21tYW5kIEFkZC1NcFByZWZlcmVuY2UgLUV4Y2x1c2lvblBhdGggJw==
		$a_81_1 = {5a 58 68 77 62 47 39 79 5a 58 49 78 4c 6d 56 34 5a 51 3d 3d } //1 ZXhwbG9yZXIxLmV4ZQ==
		$a_81_2 = {51 6d 6c 79 49 47 68 68 64 47 45 67 62 32 78 31 78 5a 39 30 64 54 6f 67 30 55 32 56 73 5a 57 4e 30 49 43 6f 67 5a 6e 4a 76 62 53 42 58 61 57 34 7a 4d 6c 39 44 62 32 31 77 64 58 52 6c 63 6c 4e 35 63 33 52 6c 62 51 3d 3d } //1 QmlyIGhhdGEgb2x1xZ90dTog0U2VsZWN0ICogZnJvbSBXaW4zMl9Db21wdXRlclN5c3RlbQ==
		$a_81_3 = {56 6d 6c 79 64 48 56 68 62 45 4a 76 65 41 3d 3d 28 55 32 56 73 5a 57 4e 30 49 43 6f 67 5a 6e 4a 76 62 53 42 58 61 57 34 7a 4d 6c 39 45 61 58 4e 72 52 48 4a 70 64 6d 55 3d } //1 VmlydHVhbEJveA==(U2VsZWN0ICogZnJvbSBXaW4zMl9EaXNrRHJpdmU=
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}