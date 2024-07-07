
rule Trojan_Win64_Ulise_DS_MTB{
	meta:
		description = "Trojan:Win64/Ulise.DS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 8b c2 49 f7 e1 49 8b c1 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 05 0f be c0 6b c8 35 41 0f b6 c1 2a c1 04 31 42 30 44 0c 08 49 ff c1 49 83 f9 06 72 } //1
		$a_01_1 = {71 58 40 71 5b 54 42 68 6e 0b 65 78 3c 00 00 00 71 58 40 51 5b 54 42 37 72 61 6d 63 5d 59 5a 56 4a 66 79 5a 4e 62 7d 3f 60 58 5e 5f 55 47 16 64 5d 5a 4f 49 55 49 47 1f 03 20 30 43 00 00 00 00 72 61 6d 75 5b 5a 52 68 6c 4b 4f 58 57 62 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}