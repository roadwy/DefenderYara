
rule Backdoor_Win32_Payduse_A_bit{
	meta:
		description = "Backdoor:Win32/Payduse.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {6e 65 74 31 20 75 73 65 72 20 67 75 65 73 74 20 67 75 65 73 74 31 32 33 21 40 23 } //01 00  net1 user guest guest123!@#
		$a_01_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 73 61 74 68 63 2e 65 78 65 20 2f 66 } //01 00  taskkill /im sathc.exe /f
		$a_01_2 = {6e 65 74 31 20 75 73 65 72 20 67 75 65 73 74 20 2f 61 63 74 69 76 65 3a 79 65 73 } //01 00  net1 user guest /active:yes
		$a_01_3 = {6e 65 74 31 20 6c 6f 63 61 6c 67 72 6f 75 70 20 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 73 20 67 75 65 73 74 20 2f 61 64 64 } //00 00  net1 localgroup administrators guest /add
	condition:
		any of ($a_*)
 
}