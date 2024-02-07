
rule Backdoor_Win32_Imecab_A{
	meta:
		description = "Backdoor:Win32/Imecab.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 65 74 20 6c 6f 63 61 6c 67 72 6f 75 70 20 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 73 20 67 75 65 73 74 20 2f 61 64 64 } //01 00  net localgroup administrators guest /add
		$a_01_1 = {53 65 44 65 6e 79 52 65 6d 6f 74 65 49 6e 74 65 72 61 63 74 69 76 65 4c 6f 67 6f 6e 52 69 67 68 74 20 3d 20 20 3e 3e 20 63 3a 5c 74 65 73 74 2e 69 6e 66 } //01 00  SeDenyRemoteInteractiveLogonRight =  >> c:\test.inf
		$a_01_2 = {53 45 43 45 44 49 54 20 2f 43 4f 4e 46 49 47 55 52 45 20 2f 43 46 47 20 63 3a 5c 74 65 73 74 2e 69 6e 66 20 2f 44 42 20 64 75 6d 6d 79 2e 73 64 62 } //01 00  SECEDIT /CONFIGURE /CFG c:\test.inf /DB dummy.sdb
		$a_01_3 = {6e 65 74 20 6c 6f 63 61 6c 67 72 6f 75 70 20 67 75 65 73 74 73 20 67 75 65 73 74 20 2f 64 65 6c } //00 00  net localgroup guests guest /del
		$a_01_4 = {00 5d } //04 00  崀
	condition:
		any of ($a_*)
 
}