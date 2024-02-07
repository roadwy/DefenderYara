
rule Trojan_Win32_VBObfuse_SM_MTB{
	meta:
		description = "Trojan:Win32/VBObfuse.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {ff 34 17 81 fa b4 78 b5 47 81 fb 66 33 e2 b3 5b 66 f7 c2 3c 9f 66 81 fb a6 af 31 f3 66 f7 c3 2e 1a 66 3d 6d 62 01 1c 10 81 fa f4 94 8e 4c 81 ff b6 d6 8e 70 83 c2 04 81 ff 9a 4c 5d 06 66 f7 c2 b1 42 81 fa 74 3c 00 00 75 b6 } //02 00 
		$a_00_1 = {ff 34 17 a9 ee ff 45 a1 66 f7 c2 ae 5d 5b 81 ff a8 87 00 05 81 fa 21 e3 ab 5a 31 f3 f7 c7 84 36 15 f9 66 3d 89 f0 01 1c 10 66 a9 39 31 81 ff 27 9c 4b 96 83 c2 04 f7 c7 a7 28 b3 40 f7 c3 5a b1 19 78 81 fa f8 3c 00 00 75 b6 } //01 00 
		$a_01_2 = {6e 00 49 00 78 00 76 00 74 00 71 00 49 00 6f 00 5a 00 4a 00 7a 00 4f 00 59 00 68 00 31 00 31 00 } //01 00  nIxvtqIoZJzOYh11
		$a_01_3 = {55 00 73 00 6c 00 69 00 6e 00 67 00 65 00 67 00 65 00 72 00 6e 00 69 00 6e 00 67 00 65 00 6e 00 36 00 } //01 00  Uslingegerningen6
		$a_01_4 = {4d 00 79 00 41 00 48 00 62 00 31 00 38 00 39 00 } //00 00  MyAHb189
	condition:
		any of ($a_*)
 
}