
rule Trojan_Win32_Emotet_PVY_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PVY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {f7 f9 8b 84 24 90 01 04 83 c0 01 89 84 24 90 01 04 8a 94 14 90 01 04 30 54 03 ff 90 09 05 00 b9 90 00 } //01 00 
		$a_81_1 = {46 61 75 31 31 52 47 55 59 66 61 6b 4b 66 68 49 77 30 54 71 52 44 38 63 57 44 41 72 4f 48 36 } //00 00 
	condition:
		any of ($a_*)
 
}