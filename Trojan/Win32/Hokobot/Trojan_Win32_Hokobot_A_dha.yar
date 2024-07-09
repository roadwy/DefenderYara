
rule Trojan_Win32_Hokobot_A_dha{
	meta:
		description = "Trojan:Win32/Hokobot.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 05 00 00 "
		
	strings :
		$a_03_0 = {81 7d 0c 04 01 00 00 74 ?? 81 7d 0c 00 01 00 00 } //10
		$a_01_1 = {23 23 44 61 74 61 23 23 3a 20 41 63 74 69 76 65 20 57 69 6e 64 6f 77 2d 2d 3e } //10 ##Data##: Active Window-->
		$a_01_2 = {53 65 74 57 69 6e 48 6f 4b } //10 SetWinHoK
		$a_01_3 = {3c 73 74 72 6f 6e 67 3e 20 5b 43 41 50 4c 4f 43 4b 5d 20 3c 2f 73 74 72 6f 6e 67 3e } //10 <strong> [CAPLOCK] </strong>
		$a_01_4 = {5c 73 65 72 76 65 72 68 65 6c 70 2e 64 6c 6c } //1 \serverhelp.dll
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1) >=41
 
}