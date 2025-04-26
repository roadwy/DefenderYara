
rule Trojan_Win32_Redline_DAC_MTB{
	meta:
		description = "Trojan:Win32/Redline.DAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {f6 17 80 2f ?? 47 e2 } //1
		$a_01_1 = {70 6c 7a 76 6f 79 66 61 62 77 6f 6d 6f 66 62 6c 69 61 6a 78 71 6d 6a 72 6a 6c 77 6d 74 75 61 63 } //1 plzvoyfabwomofbliajxqmjrjlwmtuac
		$a_01_2 = {76 73 74 66 6a 7a 72 6f 68 6e 73 70 6b 7a 62 6d 76 6e 66 71 72 68 6b 67 61 65 67 6c 73 6d 69 6b 61 6d 6f 65 7a 76 72 } //1 vstfjzrohnspkzbmvnfqrhkgaeglsmikamoezvr
		$a_01_3 = {6d 70 6f 7a 6a 61 74 63 79 74 67 6c 67 77 67 72 6f 74 78 6f 6b 6e 61 77 79 6b 6b 71 7a 69 6e 71 6b 68 75 6b 75 73 68 63 77 6a 6d 61 66 76 70 63 66 6f 6e 72 74 64 63 78 75 63 6a 79 6d 6a 68 7a 70 66 6a 62 63 76 64 76 64 70 61 71 66 68 63 6a 68 79 6a } //1 mpozjatcytglgwgrotxoknawykkqzinqkhukushcwjmafvpcfonrtdcxucjymjhzpfjbcvdvdpaqfhcjhyj
		$a_01_4 = {77 72 69 63 70 73 7a 6c 6c 62 68 61 77 63 70 79 63 77 66 6c 78 72 6a 7a 74 69 73 7a 79 63 6a 79 75 69 76 76 72 61 64 71 76 78 64 61 79 6d 76 78 } //1 wricpszllbhawcpycwflxrjztiszycjyuivvradqvxdaymvx
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}