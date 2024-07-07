
rule Trojan_Win32_Sefnit_AY{
	meta:
		description = "Trojan:Win32/Sefnit.AY,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c6 06 83 7f 14 08 72 04 8b 90 01 01 eb 02 8b 90 00 } //1
		$a_01_1 = {2d 00 2d 00 61 00 70 00 70 00 3d 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}