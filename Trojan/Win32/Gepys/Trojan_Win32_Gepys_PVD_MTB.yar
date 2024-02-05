
rule Trojan_Win32_Gepys_PVD_MTB{
	meta:
		description = "Trojan:Win32/Gepys.PVD!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {88 45 fc 8a 02 0c 01 0f b6 f8 89 d8 99 f7 ff 0f b6 39 01 f8 88 06 } //02 00 
		$a_01_1 = {8b 55 08 01 c2 8a 02 ff 4d ec 88 45 f0 8a 01 88 02 8a 55 f0 88 11 75 } //02 00 
		$a_01_2 = {8a 17 03 45 08 ff 4d f0 88 55 d7 8a 10 88 17 8a 55 d7 88 10 8b 4d d8 75 } //00 00 
	condition:
		any of ($a_*)
 
}