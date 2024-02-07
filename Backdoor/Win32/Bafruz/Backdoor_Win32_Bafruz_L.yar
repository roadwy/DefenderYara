
rule Backdoor_Win32_Bafruz_L{
	meta:
		description = "Backdoor:Win32/Bafruz.L,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {6f 6b 64 77 2e 70 68 70 3f 73 65 72 69 61 6c 3d 00 00 00 00 ff ff ff ff 04 00 00 00 26 69 64 3d } //01 00 
		$a_01_1 = {6c 31 72 65 7a 65 72 76 2e 65 78 65 } //01 00  l1rezerv.exe
		$a_01_2 = {6c 5f 72 65 7a 65 72 76 } //00 00  l_rezerv
	condition:
		any of ($a_*)
 
}