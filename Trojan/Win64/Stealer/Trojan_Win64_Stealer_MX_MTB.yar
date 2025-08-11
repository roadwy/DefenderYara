
rule Trojan_Win64_Stealer_MX_MTB{
	meta:
		description = "Trojan:Win64/Stealer.MX!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 39 c8 0f 84 17 94 09 00 66 89 10 0f b7 50 0a 48 83 c0 02 66 85 d2 } //1
		$a_01_1 = {52 75 6e 74 69 6e 65 20 42 72 6f 6b 65 72 2e 65 78 65 } //1 Runtine Broker.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win64_Stealer_MX_MTB_2{
	meta:
		description = "Trojan:Win64/Stealer.MX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4d 79 53 65 63 72 65 74 4c 6f 61 64 65 72 4b 65 79 31 32 33 00 00 00 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 00 00 00 43 00 3a 00 5c 00 00 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 56 00 4d 00 77 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}