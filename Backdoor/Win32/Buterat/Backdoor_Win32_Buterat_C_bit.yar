
rule Backdoor_Win32_Buterat_C_bit{
	meta:
		description = "Backdoor:Win32/Buterat.C!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 00 69 00 75 00 6c 00 69 00 61 00 6e 00 67 00 62 00 61 00 6f 00 } //01 00  liuliangbao
		$a_01_1 = {53 00 43 00 43 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 64 00 61 00 74 00 } //01 00  SCConfig.dat
		$a_01_2 = {43 00 46 00 47 00 55 00 70 00 64 00 61 00 74 00 65 00 } //01 00  CFGUpdate
		$a_01_3 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //00 00  Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		any of ($a_*)
 
}