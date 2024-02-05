
rule Trojan_Win32_Injector_RPV_MTB{
	meta:
		description = "Trojan:Win32/Injector.RPV!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 50 46 30 06 54 46 6f 72 6d 32 05 46 6f 72 6d 32 04 4c 65 66 74 03 ee 00 03 54 6f 70 03 a8 00 05 57 69 64 74 68 03 f8 02 06 48 65 69 67 68 74 03 cf 01 07 43 61 70 74 69 6f 6e 06 05 46 6f 72 6d 32 } //00 00 
	condition:
		any of ($a_*)
 
}