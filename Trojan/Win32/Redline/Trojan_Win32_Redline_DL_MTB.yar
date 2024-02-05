
rule Trojan_Win32_Redline_DL_MTB{
	meta:
		description = "Trojan:Win32/Redline.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 49 00 8a 8c 02 3b 2d 0b 00 88 0c 30 40 3b 05 7c } //00 00 
	condition:
		any of ($a_*)
 
}