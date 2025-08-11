
rule Ransom_Win64_Lynx_YAE_MTB{
	meta:
		description = "Ransom:Win64/Lynx.YAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 00 6c 00 79 00 6e 00 78 00 } //1 .lynx
		$a_01_1 = {2d 00 2d 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 2d 00 6e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 } //1 --encrypt-network
		$a_01_2 = {52 00 45 00 41 00 44 00 4d 00 45 00 2e 00 74 00 78 00 74 00 } //1 README.txt
		$a_01_3 = {2d 00 2d 00 6e 00 6f 00 2d 00 62 00 61 00 63 00 6b 00 67 00 72 00 6f 00 75 00 6e 00 64 00 } //1 --no-background
		$a_01_4 = {52 32 39 76 5a 43 42 68 5a 6e 52 6c 63 6d 35 76 62 32 34 73 49 48 64 6c 49 47 46 79 5a 53 42 4d 65 57 35 34 49 45 64 79 62 33 56 77 4c 67 30 4b } //10 R29vZCBhZnRlcm5vb24sIHdlIGFyZSBMeW54IEdyb3VwLg0K
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*10) >=14
 
}