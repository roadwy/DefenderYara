
rule Trojan_Win32_Killav_DO{
	meta:
		description = "Trojan:Win32/Killav.DO,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 45 f9 61 c6 45 fa 62 c6 45 fb 6c c6 45 fc 65 c6 45 fd 64 } //03 00 
		$a_03_1 = {76 10 80 04 3e fd 57 46 e8 90 01 03 00 3b f0 59 72 f0 90 00 } //01 00 
		$a_09_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 } //00 00 
	condition:
		any of ($a_*)
 
}