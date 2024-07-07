
rule Trojan_Win32_Agent_AAH{
	meta:
		description = "Trojan:Win32/Agent.AAH,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 e8 05 74 2c 48 74 5f 83 e8 51 74 7e 83 e8 24 74 67 } //1
		$a_01_1 = {49 6e 74 65 72 6e 65 74 20 43 6f 6e 6e 65 63 74 69 6f 6e 20 53 68 61 72 69 6e 67 20 28 49 43 41 29 } //1 Internet Connection Sharing (ICA)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}