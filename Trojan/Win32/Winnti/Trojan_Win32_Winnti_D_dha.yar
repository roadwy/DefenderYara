
rule Trojan_Win32_Winnti_D_dha{
	meta:
		description = "Trojan:Win32/Winnti.D!dha,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 69 6e 64 20 73 79 73 74 65 6d 20 73 76 63 68 6f 73 74 2e 65 78 65 } //01 00  find system svchost.exe
		$a_01_1 = {47 65 74 53 79 73 74 65 6d 73 76 63 48 6f 73 74 50 72 6f 63 65 73 73 49 64 20 52 65 74 75 72 6e 20 25 64 } //01 00  GetSystemsvcHostProcessId Return %d
		$a_01_2 = {53 74 61 72 74 49 6e 6a 65 63 74 20 25 73 20 74 6f 20 25 64 20 53 75 63 63 65 73 73 21 } //01 00  StartInject %s to %d Success!
		$a_01_3 = {44 65 6c 65 74 65 4d 79 73 65 6c 66 20 4f 76 65 72 21 } //00 00  DeleteMyself Over!
	condition:
		any of ($a_*)
 
}