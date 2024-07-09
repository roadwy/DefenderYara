
rule Trojan_Win32_GreenBug_A{
	meta:
		description = "Trojan:Win32/GreenBug.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {a1 10 f8 dd 00 83 c0 01 a3 10 f8 dd 00 83 3d 10 f8 dd 00 40 75 0a c7 05 10 f8 dd 00 00 00 00 00 8b 0d 10 f8 dd 00 69 c9 2c 01 00 00 8a 55 08 88 91 2c 64 d9 00 a1 10 f8 dd 00 69 c0 2c 01 00 00 c6 80 2d 64 d9 00 00 a1 10 f8 dd 00 69 c0 2c 01 00 00 05 2c 64 d9 00 } //1
		$a_03_1 = {83 c4 04 50 6a ?? e8 20 ?? ?? ?? 83 c4 04 50 6a ?? e8 15 ?? ?? ?? 83 c4 04 50 6a ?? e8 0a ?? ?? ?? 83 c4 04 50 6a ?? e8 ff ?? ?? ?? 83 c4 04 50 6a ?? e8 f4 ?? ?? ?? 83 c4 04 50 6a ?? e8 e9 } //1
		$a_01_2 = {54 75 72 6e 20 6f 66 66 20 74 68 65 20 74 65 6c 65 76 69 73 69 6f 6e 20 61 73 20 69 74 20 69 73 20 6f 6e 6c 79 20 61 20 66 6c 61 73 68 69 6e 67 20 62 6f 78 20 64 69 73 74 72 61 63 74 69 6f 6e 20 66 72 6f 6d 20 6c 69 66 65 21 20 49 6e 74 65 72 61 63 74 } //1 Turn off the television as it is only a flashing box distraction from life! Interact
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}