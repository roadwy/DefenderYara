
rule Trojan_Win32_Small_GP_dll{
	meta:
		description = "Trojan:Win32/Small.GP!dll,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {5a 38 3d 3b 58 6a 6d 6e 46 64 65 48 67 6a 78 78 } //01 00  Z8=;XjmnFdeHgjxx
		$a_01_1 = {58 44 4d 5f 5c 4a 59 4e 57 57 38 3d 3b 58 6a 6d 6e } //01 00  XDM_\JYNWW8=;Xjmn
		$a_01_2 = {c3 bc bd a3 00 } //01 00 
		$a_01_3 = {38 3d 3b 7f 79 6a 72 25 6e 73 6e 00 } //01 00  㴸缻橹╲獮n
		$a_03_4 = {7b 41 43 43 41 45 32 44 32 2d 30 35 90 01 02 2d 90 01 04 2d 41 34 33 45 2d 90 01 02 44 31 38 42 42 37 39 39 90 01 02 7d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}