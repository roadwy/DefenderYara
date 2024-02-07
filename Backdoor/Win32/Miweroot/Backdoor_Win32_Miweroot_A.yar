
rule Backdoor_Win32_Miweroot_A{
	meta:
		description = "Backdoor:Win32/Miweroot.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 3a 2f 2f 2b 3a 34 34 33 } //01 00  s://+:443
		$a_01_1 = {48 74 74 70 41 64 64 55 72 6c 20 66 61 69 6c 65 64 20 77 69 74 68 20 25 6c 75 } //01 00  HttpAddUrl failed with %lu
		$a_01_2 = {65 72 20 66 69 6c 65 20 69 73 20 74 72 61 6e 73 66 65 72 69 6e 67 2c 77 61 69 74 20 61 6e 64 20 72 65 74 72 79 2e } //01 00  er file is transfering,wait and retry.
		$a_01_3 = {65 6e 20 6f 6e 3a 20 25 73 2c 77 61 69 74 20 63 6f 6e 6e 65 63 74 2e 2e 2e } //01 00  en on: %s,wait connect...
		$a_01_4 = {25 73 28 25 75 2e 25 75 2e 25 75 2e 25 75 29 20 63 6f 6e 6e 65 63 74 65 64 2e } //01 00  %s(%u.%u.%u.%u) connected.
		$a_01_5 = {31 2e 33 2e 36 2e 31 2e 35 2e 35 2e 37 2e 33 2e 31 } //01 00  1.3.6.1.5.5.7.3.1
		$a_01_6 = {25 64 20 25 73 46 69 6c 65 2f } //01 00  %d %sFile/
		$a_01_7 = {44 6f 46 69 6c 65 54 72 61 6e 73 66 65 72 3a } //01 00  DoFileTransfer:
		$a_01_8 = {65 72 20 54 69 6d 65 6f 75 74 2c 46 69 6c 65 20 25 73 20 66 61 69 6c 65 64 21 } //01 00  er Timeout,File %s failed!
		$a_01_9 = {6c 65 20 25 73 20 73 75 63 63 65 73 73 65 64 21 } //01 00  le %s successed!
		$a_01_10 = {25 30 32 64 25 30 32 64 25 30 32 64 25 30 32 64 25 30 32 64 25 30 32 64 2e 74 78 74 } //00 00  %02d%02d%02d%02d%02d%02d.txt
	condition:
		any of ($a_*)
 
}