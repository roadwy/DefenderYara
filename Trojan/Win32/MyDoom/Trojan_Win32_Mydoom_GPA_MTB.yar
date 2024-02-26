
rule Trojan_Win32_Mydoom_GPA_MTB{
	meta:
		description = "Trojan:Win32/Mydoom.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {8a 8f 68 91 50 00 80 f1 90 01 01 88 8c 05 fc fd ff ff 40 3d 00 02 00 00 89 45 fc 7c 18 8d 4d fc 6a 00 51 50 8d 85 fc fd ff ff 50 ff 75 08 ff d6 33 c0 89 45 fc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}