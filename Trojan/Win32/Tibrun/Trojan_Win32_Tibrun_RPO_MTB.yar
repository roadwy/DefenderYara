
rule Trojan_Win32_Tibrun_RPO_MTB{
	meta:
		description = "Trojan:Win32/Tibrun.RPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 17 33 d0 89 17 83 c7 04 e2 f5 } //01 00 
		$a_01_1 = {89 45 e4 33 c0 8b 00 ff 75 e4 } //01 00 
		$a_01_2 = {41 64 64 56 65 63 74 6f 72 65 64 45 78 63 65 70 74 69 6f 6e 48 61 6e 64 6c 65 72 } //01 00  AddVectoredExceptionHandler
		$a_01_3 = {52 65 6d 6f 76 65 56 65 63 74 6f 72 65 64 45 78 63 65 70 74 69 6f 6e 48 61 6e 64 6c 65 72 } //00 00  RemoveVectoredExceptionHandler
	condition:
		any of ($a_*)
 
}