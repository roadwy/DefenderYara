
rule Backdoor_Win32_Nuwar_A{
	meta:
		description = "Backdoor:Win32/Nuwar.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 0a 00 00 02 00 "
		
	strings :
		$a_01_0 = {e3 32 49 8b 34 8b 03 f5 33 ff fc 33 c0 ac 3a c4 74 07 c1 cf 0d 03 f8 eb f2 } //02 00 
		$a_01_1 = {77 07 0f be c0 83 e8 30 c3 56 33 f6 3c 41 7c 04 3c 46 7e 15 } //03 00 
		$a_03_2 = {2e 69 6e 69 00 00 90 02 02 5b 62 6c 61 63 6b 6c 69 73 74 5d 90 00 } //01 00 
		$a_01_3 = {5b 70 65 65 72 73 5d } //01 00  [peers]
		$a_00_4 = {43 6f 75 6e 74 65 72 3d 30 } //01 00  Counter=0
		$a_00_5 = {5b 63 6f 75 6e 74 65 72 5d } //01 00  [counter]
		$a_01_6 = {57 69 6e 25 73 20 25 64 2e 25 64 } //01 00  Win%s %d.%d
		$a_01_7 = {54 43 50 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 69 73 20 66 61 69 6c 65 64 } //02 00  TCP connection is failed
		$a_01_8 = {6e 6f 72 65 70 6c 79 00 40 61 76 70 2e 00 } //02 00  潮敲汰y慀灶.
		$a_01_9 = {57 69 6e 64 6f 73 73 20 4e 54 } //00 00  Windoss NT
	condition:
		any of ($a_*)
 
}