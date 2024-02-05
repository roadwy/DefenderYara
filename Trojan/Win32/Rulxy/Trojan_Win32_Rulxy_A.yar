
rule Trojan_Win32_Rulxy_A{
	meta:
		description = "Trojan:Win32/Rulxy.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 2e 69 63 6f 0f 84 90 01 02 00 00 3d 2e 63 6c 72 0f 84 90 01 02 00 00 3d 2e 78 6d 6c 0f 84 90 01 02 00 00 25 ff ff ff 00 3d 2e 6a 73 00 0f 84 90 01 02 00 00 90 00 } //01 00 
		$a_03_1 = {3d 47 45 54 20 74 90 01 01 3d 50 4f 53 54 75 90 01 01 80 7f 04 20 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}