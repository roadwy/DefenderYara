
rule Trojan_BAT_XWorm_AXW_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AXW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 16 0b 2b 2d 06 07 9a 0c 72 ?? 00 00 70 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 8c ?? 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a de 03 26 de 00 07 17 58 } //2
		$a_01_1 = {61 00 31 00 30 00 34 00 34 00 32 00 31 00 36 00 2e 00 78 00 73 00 70 00 68 00 2e 00 72 00 75 00 2f 00 } //1 a1044216.xsph.ru/
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_XWorm_AXW_MTB_2{
	meta:
		description = "Trojan:BAT/XWorm.AXW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 38 38 64 36 30 65 64 2d 61 37 37 61 2d 34 37 32 34 2d 38 31 35 38 2d 37 38 66 33 38 65 37 66 62 32 39 38 } //1 a88d60ed-a77a-4724-8158-78f38e7fb298
		$a_01_1 = {49 6d 6d 6f 62 69 6c 69 57 69 6e 46 6f 72 6d 73 2e 46 6f 72 6d 54 69 70 6f 49 6d 6d 6f 62 69 6c 65 2e 72 65 73 6f 75 72 63 65 73 } //2 ImmobiliWinForms.FormTipoImmobile.resources
		$a_01_2 = {49 6d 6d 6f 62 69 6c 69 57 69 6e 46 6f 72 6d 73 2e 4e 75 6f 76 6f 49 6d 6d 6f 62 69 6c 65 2e 72 65 73 6f 75 72 63 65 73 } //2 ImmobiliWinForms.NuovoImmobile.resources
		$a_01_3 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 50 00 72 00 6f 00 70 00 72 00 69 00 65 00 74 00 61 00 72 00 69 00 } //1 SELECT * FROM Proprietari
		$a_01_4 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 54 00 69 00 70 00 69 00 49 00 6d 00 6d 00 6f 00 62 00 69 00 6c 00 65 00 } //1 SELECT * FROM TipiImmobile
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}