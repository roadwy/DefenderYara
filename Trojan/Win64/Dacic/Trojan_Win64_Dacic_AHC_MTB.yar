
rule Trojan_Win64_Dacic_AHC_MTB{
	meta:
		description = "Trojan:Win64/Dacic.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 4c 4c 20 50 72 6f 78 79 20 45 72 72 6f 72 } //20 DLL Proxy Error
		$a_01_1 = {46 61 69 6c 65 64 20 74 6f 20 67 65 74 20 61 64 64 72 65 73 73 20 6f 66 20 63 75 72 6c 5f 65 61 73 79 5f 73 65 74 6f 70 74 } //30 Failed to get address of curl_easy_setopt
		$a_01_2 = {48 89 55 e0 48 8b 00 48 89 45 e8 48 8b 4d e8 8b 55 18 48 8b 45 10 4c 8b 4d f0 49 89 c8 48 89 c1 41 ff d1 } //50
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*30+(#a_01_2  & 1)*50) >=100
 
}