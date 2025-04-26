
rule Trojan_Win64_Alureon_gen_D{
	meta:
		description = "Trojan:Win64/Alureon.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {30 0a 48 83 c2 01 44 3b c0 72 ed 80 3b 4d 75 ?? 80 7b 01 5a } //2
		$a_03_1 = {0f b7 69 3c 48 8b f1 66 81 7c 29 18 0b 01 74 07 33 c0 e9 ?? ?? ?? ?? 8b 54 29 50 48 8b 4c 29 30 } //1
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 54 6f 46 53 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}