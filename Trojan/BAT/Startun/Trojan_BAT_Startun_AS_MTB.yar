
rule Trojan_BAT_Startun_AS_MTB{
	meta:
		description = "Trojan:BAT/Startun.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 "
		
	strings :
		$a_80_0 = {4e 69 74 72 6f 20 47 65 6e 65 72 61 74 6f 72 5f 50 72 6f 63 65 73 73 65 64 42 79 46 6f 64 79 } //Nitro Generator_ProcessedByFody  3
		$a_80_1 = {52 65 61 64 45 78 69 73 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //ReadExistingAssembly  3
		$a_80_2 = {52 65 61 64 46 72 6f 6d 45 6d 62 65 64 64 65 64 52 65 73 6f 75 72 63 65 73 } //ReadFromEmbeddedResources  3
		$a_80_3 = {43 6f 6e 74 61 69 6e 73 4b 65 79 } //ContainsKey  3
		$a_80_4 = {63 6f 73 74 75 72 61 2e 69 6e 6a 65 63 74 6f 72 64 6c 6c 2e 64 6c 6c } //costura.injectordll.dll  3
		$a_80_5 = {75 6e 69 71 75 65 49 64 } //uniqueId  3
		$a_80_6 = {63 6f 73 74 75 72 61 2e 69 6e 6a 65 63 74 6f 72 64 6c 6c 2e 70 64 62 } //costura.injectordll.pdb  3
		$a_80_7 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //GetExecutingAssembly  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3) >=24
 
}