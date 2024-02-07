
rule Trojan_Win32_Chapak_DY_MTB{
	meta:
		description = "Trojan:Win32/Chapak.DY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 84 07 3b 2d 0b 00 8b 0d 90 02 04 88 04 0f 83 3d 90 02 04 44 75 22 90 00 } //01 00 
		$a_01_1 = {81 ac 24 c0 01 00 00 03 c3 34 51 81 84 24 38 02 00 00 b8 20 fe 10 81 84 24 c0 01 00 00 ed a0 99 07 81 84 24 9c 00 00 00 80 a7 6e 68 81 84 24 c8 01 00 00 4b 8f 59 6d 81 84 24 6c 01 00 00 8c d4 9e 15 81 44 24 78 31 ae 7e 60 } //01 00 
		$a_01_2 = {81 ff 92 b4 e7 00 7f 0d 47 81 ff 86 4b ec 5a 0f 8c } //01 00 
		$a_01_3 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //01 00  GetTickCount
		$a_01_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00  IsDebuggerPresent
	condition:
		any of ($a_*)
 
}