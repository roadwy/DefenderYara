
rule Trojan_Win32_Emotet_DFO_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {03 c1 b9 7f 08 00 00 99 f7 f9 8b 44 24 20 8a 4c 14 24 30 08 } //01 00 
		$a_81_1 = {33 35 74 65 38 6e 64 33 54 48 41 6d 72 4e 56 58 51 4c 59 39 7a 53 44 45 4a 50 63 38 74 33 30 38 52 39 } //00 00 
	condition:
		any of ($a_*)
 
}