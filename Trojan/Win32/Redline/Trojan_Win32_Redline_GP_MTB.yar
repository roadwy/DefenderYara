
rule Trojan_Win32_Redline_GP_MTB{
	meta:
		description = "Trojan:Win32/Redline.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4d 10 8a 14 11 88 55 f3 0f b6 45 f3 8b 4d 08 03 4d dc 0f b6 11 33 d0 8b 45 08 03 45 dc 88 10 } //00 00 
	condition:
		any of ($a_*)
 
}