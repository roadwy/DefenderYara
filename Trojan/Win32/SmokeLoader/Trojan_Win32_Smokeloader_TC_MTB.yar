
rule Trojan_Win32_Smokeloader_TC_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.TC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {c1 e1 04 03 4d f0 c1 e8 05 03 45 ec 33 ca 33 c1 89 4d 08 89 45 0c } //0a 00 
		$a_03_1 = {8d 4d fc 51 90 0a 51 00 c6 05 90 01 04 6c c6 05 90 01 04 63 c6 05 90 01 04 74 c6 05 90 01 04 74 c6 05 90 01 04 72 c6 05 90 01 04 72 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}