
rule Trojan_BAT_Bobik_ARA_MTB{
	meta:
		description = "Trojan:BAT/Bobik.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {5c 4f 6c 69 6d 70 6f 6b 73 31 30 2e 70 64 62 } //2 \Olimpoks10.pdb
		$a_80_1 = {43 3a 5c 53 79 73 74 65 6d 5c 66 69 6c 65 73 63 72 65 65 6e 73 68 6f 74 } //C:\System\filescreenshot  2
		$a_80_2 = {4c 6f 67 69 6e } //Login  2
		$a_80_3 = {50 61 73 73 77 6f 72 64 } //Password  2
		$a_80_4 = {55 73 65 72 6e 65 6d 65 2f 69 64 } //Userneme/id  2
		$a_80_5 = {44 65 78 56 69 6e } //DexVin  2
	condition:
		((#a_01_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2) >=12
 
}