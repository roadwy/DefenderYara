
rule Trojan_Win64_Alureon_D{
	meta:
		description = "Trojan:Win64/Alureon.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 00 20 00 75 00 61 00 63 00 36 00 34 00 6f 00 6b 00 00 00 } //1
		$a_03_1 = {41 b9 00 30 00 00 41 b8 06 01 00 00 c7 44 24 ?? 04 00 00 00 ff 15 ?? ?? ?? ?? 48 8b f0 48 3b c3 0f 84 ?? ?? 00 00 48 83 c9 ff 33 c0 48 8b fd 66 f2 af 48 8d 44 24 ?? 4c 8b c5 48 f7 d1 48 8b d6 48 89 44 24 ?? 4c 8d 0c 09 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}