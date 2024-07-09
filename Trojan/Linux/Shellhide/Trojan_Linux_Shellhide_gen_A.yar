
rule Trojan_Linux_Shellhide_gen_A{
	meta:
		description = "Trojan:Linux/Shellhide.gen!A,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 } //1 Sub Auto_Open()
		$a_02_1 = {53 68 65 6c 6c 28 43 68 72 6f 6d 65 [0-02] 2c 20 76 62 48 69 64 65 29 } //1
		$a_00_2 = {45 6e 76 69 72 6f 6e 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 } //1 Environ("USERPROFILE")
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}