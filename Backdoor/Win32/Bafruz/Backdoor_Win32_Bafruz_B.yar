
rule Backdoor_Win32_Bafruz_B{
	meta:
		description = "Backdoor:Win32/Bafruz.B,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 03 00 "
		
	strings :
		$a_01_0 = {62 61 7a 61 2d 34 34 2e 72 75 } //02 00  baza-44.ru
		$a_01_1 = {66 69 6e 64 5f 61 76 5f 76 65 72 28 72 53 65 61 72 63 68 52 65 63 2e 4e 61 6d 65 2c 20 41 56 5f 49 44 2c 20 41 56 5f 56 45 52 29 } //02 00  find_av_ver(rSearchRec.Name, AV_ID, AV_VER)
		$a_01_2 = {66 69 72 65 77 61 6c 6c 20 73 65 74 20 6f 70 6d 6f 64 65 20 6d 6f 64 65 3d 64 69 73 61 62 6c 65 } //02 00  firewall set opmode mode=disable
		$a_81_3 = {4b 41 56 5f 55 4e 49 4e 53 54 41 4c 4c } //03 00  KAV_UNINSTALL
		$a_00_4 = {78 70 64 72 76 73 64 2e 65 78 65 00 } //02 00 
		$a_00_5 = {77 69 6e 73 65 74 75 70 61 70 69 2e 6c 6f 67 00 } //00 00 
	condition:
		any of ($a_*)
 
}