
rule Trojan_Win32_Nitol_RJ_MTB{
	meta:
		description = "Trojan:Win32/Nitol.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 6a 79 2e 6c 6e 6b } //01 00  C:\ProgramData\jy.lnk
		$a_01_1 = {46 3a 5c 68 61 63 6b 73 68 65 6e 2e 65 78 65 } //01 00  F:\hackshen.exe
		$a_01_2 = {3a 39 38 37 34 2f 41 6e 79 44 65 73 6b 2e 65 78 65 } //00 00  :9874/AnyDesk.exe
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Nitol_RJ_MTB_2{
	meta:
		description = "Trojan:Win32/Nitol.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 52 45 56 45 44 21 20 49 20 53 4d 4f 4b 45 20 47 41 4e 4a 41 20 45 56 45 52 59 20 44 41 59 21 } //01 00  PREVED! I SMOKE GANJA EVERY DAY!
		$a_01_1 = {73 64 63 6d 62 78 74 72 67 6b 68 32 } //01 00  sdcmbxtrgkh2
		$a_01_2 = {70 76 74 66 6e 74 6e 72 78 76 6d 73 63 70 68 6b 67 62 66 74 64 5f } //00 00  pvtfntnrxvmscphkgbftd_
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Nitol_RJ_MTB_3{
	meta:
		description = "Trojan:Win32/Nitol.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 35 00 34 00 2e 00 32 00 31 00 31 00 2e 00 31 00 34 00 2e 00 39 00 31 00 2f 00 77 00 6f 00 72 00 64 00 2e 00 65 00 78 00 65 00 } //01 00  http://154.211.14.91/word.exe
		$a_01_1 = {57 69 6e 64 6f 77 73 50 72 6f 6a 65 63 74 38 2e 70 64 62 } //00 00  WindowsProject8.pdb
	condition:
		any of ($a_*)
 
}