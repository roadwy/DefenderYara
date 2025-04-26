
rule Trojan_Win32_Sefnit_BT{
	meta:
		description = "Trojan:Win32/Sefnit.BT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 5d e4 83 7f 14 08 72 04 8b 0f eb 02 8b cf 6a 22 } //1
		$a_01_1 = {2d 00 2d 00 61 00 70 00 70 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}