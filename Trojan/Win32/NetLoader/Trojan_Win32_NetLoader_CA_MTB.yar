
rule Trojan_Win32_NetLoader_CA_MTB{
	meta:
		description = "Trojan:Win32/NetLoader.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 01 00 "
		
	strings :
		$a_81_0 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //01 00  \\.\PhysicalDrive0
		$a_81_1 = {44 3a 5c 63 61 6e 67 6b 75 5c 57 69 6e 4f 73 43 6c 69 65 6e 74 50 72 6f 6a 65 63 74 5c 52 65 6c 65 61 73 65 2d 65 78 65 5c } //01 00  D:\cangku\WinOsClientProject\Release-exe\
		$a_81_2 = {4b 37 54 53 65 63 75 72 69 74 79 2e 65 78 65 } //01 00  K7TSecurity.exe
		$a_81_3 = {66 2d 73 65 63 75 72 65 2e 65 78 65 } //01 00  f-secure.exe
		$a_81_4 = {51 75 69 63 6b 48 65 61 6c } //01 00  QuickHeal
		$a_81_5 = {48 41 52 44 57 41 52 45 5c 44 45 53 43 52 49 50 54 49 4f 4e 5c 53 79 73 74 65 6d 5c 43 65 6e 74 72 61 6c 50 72 6f 63 65 73 73 6f 72 5c 30 } //01 00  HARDWARE\DESCRIPTION\System\CentralProcessor\0
		$a_81_6 = {58 50 2d 73 70 31 } //01 00  XP-sp1
		$a_81_7 = {56 69 73 74 61 2d 73 70 31 } //01 00  Vista-sp1
		$a_81_8 = {56 4d 77 61 72 65 53 65 72 76 69 63 65 2e 65 78 65 } //01 00  VMwareService.exe
		$a_81_9 = {5b 74 61 62 5d } //01 00  [tab]
		$a_81_10 = {5b 65 6e 74 65 72 5d } //01 00  [enter]
		$a_81_11 = {41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 73 79 73 2e 6b 65 79 } //00 00  Application Data\sys.key
	condition:
		any of ($a_*)
 
}