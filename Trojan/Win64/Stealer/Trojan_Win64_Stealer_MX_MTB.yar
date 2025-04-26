
rule Trojan_Win64_Stealer_MX_MTB{
	meta:
		description = "Trojan:Win64/Stealer.MX!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 39 c8 0f 84 17 94 09 00 66 89 10 0f b7 50 0a 48 83 c0 02 66 85 d2 } //1
		$a_01_1 = {52 75 6e 74 69 6e 65 20 42 72 6f 6b 65 72 2e 65 78 65 } //1 Runtine Broker.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}