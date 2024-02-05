
rule Trojan_Win32_Redline_NX_MTB{
	meta:
		description = "Trojan:Win32/Redline.NX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {88 d9 8a 68 01 31 f1 66 89 08 0f b6 4d 02 30 48 02 eb 99 } //0a 00 
		$a_03_1 = {8b 45 e4 8b 0c b8 31 c0 8d b4 26 90 01 05 0f b6 14 86 30 14 01 83 c0 90 01 01 8b 13 39 d0 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}