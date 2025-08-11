
rule Trojan_Win32_Matanbuchus_GTD_MTB{
	meta:
		description = "Trojan:Win32/Matanbuchus.GTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 04 68 00 30 00 00 68 00 00 10 00 6a 00 6a 00 6a 00 e8 ?? ?? ?? ?? 83 c4 08 ff d0 } //5
		$a_01_1 = {ba 04 00 00 00 6b c2 00 8b 4d f4 8b 54 01 10 89 55 e4 83 7d 0c 00 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}