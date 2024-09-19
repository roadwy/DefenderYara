
rule Trojan_Win32_FileCoder_NF_MTB{
	meta:
		description = "Trojan:Win32/FileCoder.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {4b 71 78 2b 76 4f 55 4c 36 35 42 } //2 Kqx+vOUL65B
		$a_01_1 = {4b 69 2d 6d 55 58 4b 34 53 } //2 Ki-mUXK4S
		$a_01_2 = {71 51 66 32 6b 4f 66 } //2 qQf2kOf
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}
rule Trojan_Win32_FileCoder_NF_MTB_2{
	meta:
		description = "Trojan:Win32/FileCoder.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {e9 c1 00 00 00 83 65 c0 00 c7 45 c4 0f 2c 42 00 a1 ?? ?? ?? ?? 8d 4d c0 33 c1 89 45 ?? 8b 45 18 89 45 ?? 8b 45 0c 89 } //5
		$a_01_1 = {65 6e 63 72 79 70 74 65 64 2d 6e 6f 74 2d 77 61 6c 6c 2e 65 78 65 } //1 encrypted-not-wall.exe
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}