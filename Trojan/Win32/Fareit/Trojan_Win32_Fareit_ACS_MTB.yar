
rule Trojan_Win32_Fareit_ACS_MTB{
	meta:
		description = "Trojan:Win32/Fareit.ACS!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {0f b6 42 03 0c 7f 83 c4 04 8b 44 28 85 03 80 3d fc ff ff 66 f7 d0 fc 33 c4 66 a9 ff ff fc 75 10 } //0a 00 
		$a_01_1 = {83 e8 03 03 c1 03 d1 ba 18 00 00 00 3d fd 0f 00 00 0f 84 b0 } //00 00 
	condition:
		any of ($a_*)
 
}