
rule Trojan_Win64_T1562_002_DisableWindowsEventLogging_A{
	meta:
		description = "Trojan:Win64/T1562_002_DisableWindowsEventLogging.A,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {65 00 76 00 65 00 6e 00 74 00 3a 00 3a 00 64 00 72 00 6f 00 70 00 } //00 00 
	condition:
		any of ($a_*)
 
}