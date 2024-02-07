
rule Trojan_Win64_BumbleBee_EB_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 76 66 31 38 30 74 65 36 2e 64 6c 6c } //01 00  uvf180te6.dll
		$a_01_1 = {4a 7a 47 62 45 55 38 6d } //01 00  JzGbEU8m
		$a_01_2 = {51 55 6b 30 32 34 } //01 00  QUk024
		$a_01_3 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_01_4 = {52 74 6c 4c 6f 6f 6b 75 70 46 75 6e 63 74 69 6f 6e 45 6e 74 72 79 } //01 00  RtlLookupFunctionEntry
		$a_01_5 = {52 74 6c 56 69 72 74 75 61 6c 55 6e 77 69 6e 64 } //00 00  RtlVirtualUnwind
	condition:
		any of ($a_*)
 
}