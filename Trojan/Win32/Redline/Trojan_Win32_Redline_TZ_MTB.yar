
rule Trojan_Win32_Redline_TZ_MTB{
	meta:
		description = "Trojan:Win32/Redline.TZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 45 08 8b 4d 0c 31 08 5d } //01 00 
		$a_03_1 = {8b 45 dc 8d 0c 07 33 4d 90 01 01 89 35 90 01 04 89 4d 90 01 01 8b 45 90 01 01 01 05 90 01 04 51 8d 45 90 01 01 50 e8 90 01 04 8b 5d 90 01 01 8b fb c1 e7 90 01 01 81 3d 90 01 08 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}