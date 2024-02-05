
rule Trojan_Win32_Emotet_BF_MTB{
	meta:
		description = "Trojan:Win32/Emotet.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c0 88 04 90 01 01 40 3d 03 84 01 00 7c 90 00 } //01 00 
		$a_00_1 = {b9 03 84 01 00 03 c3 99 f7 f9 8b da } //01 00 
		$a_02_2 = {6a 40 6a 4d 6a 41 68 00 00 80 00 68 90 01 04 68 90 02 06 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}