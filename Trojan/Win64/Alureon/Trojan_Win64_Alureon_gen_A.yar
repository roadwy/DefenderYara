
rule Trojan_Win64_Alureon_gen_A{
	meta:
		description = "Trojan:Win64/Alureon.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 40 10 74 c6 40 11 64 41 8a da 45 8a ea 45 8a e2 c6 40 12 6c } //1
		$a_01_1 = {3c 0d 75 06 c6 03 00 48 ff c3 80 3b 0a } //1
		$a_03_2 = {0f b7 47 06 48 83 c6 28 ff c5 4c 03 d9 3b e8 72 ?? 48 63 41 3c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}