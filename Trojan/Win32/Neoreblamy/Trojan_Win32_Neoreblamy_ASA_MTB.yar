
rule Trojan_Win32_Neoreblamy_ASA_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.ASA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {42 6e 65 6c 71 62 52 76 4d 74 6f 45 57 50 42 55 62 67 79 75 62 48 79 42 4a 70 4a 47 45 42 } //1 BnelqbRvMtoEWPBUbgyubHyBJpJGEB
		$a_01_1 = {68 75 58 6b 77 7a 65 6f 75 6f 6e 69 78 6c 6d 57 7a } //1 huXkwzeouonixlmWz
		$a_01_2 = {66 77 4c 59 44 55 5a 55 63 6f 59 65 44 46 59 6b 42 6f 4f 56 68 4e 6f 6d 54 47 4f 4c 61 50 6e 6f 76 4e } //1 fwLYDUZUcoYeDFYkBoOVhNomTGOLaPnovN
		$a_01_3 = {6d 67 6e 56 50 63 72 4c 69 68 41 47 7a 4d 62 56 5a 41 6d 56 56 42 52 65 63 56 79 4a } //1 mgnVPcrLihAGzMbVZAmVVBRecVyJ
		$a_01_4 = {59 67 79 6d 76 57 59 6c 56 68 46 43 6b 67 78 71 6f 64 71 48 4d 65 76 42 54 4e 4f 4f } //1 YgymvWYlVhFCkgxqodqHMevBTNOO
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}