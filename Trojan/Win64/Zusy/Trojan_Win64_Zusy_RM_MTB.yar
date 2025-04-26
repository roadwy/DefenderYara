
rule Trojan_Win64_Zusy_RM_MTB{
	meta:
		description = "Trojan:Win64/Zusy.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {4e 65 65 6b 72 6f 41 67 61 69 6e 5c 44 65 73 6b 74 6f 70 5c 65 73 70 20 2b 20 61 69 6d 20 6d 65 75 20 75 6c 74 69 6d 6f 5c 65 73 70 20 66 69 6e 61 6c 20 74 65 73 74 61 72 20 63 6f 69 73 61 73 20 2d 20 43 6f 70 69 61 20 2d 20 43 6f 70 69 61 20 2d 20 43 6f 70 69 61 20 2d 20 43 6f 70 69 61 5c 56 61 6c 6f 72 61 6e 74 2d 45 78 74 65 72 6e 61 6c 2d 6d 61 69 6e 5c 78 36 34 5c 52 65 6c 65 61 73 65 } //1 NeekroAgain\Desktop\esp + aim meu ultimo\esp final testar coisas - Copia - Copia - Copia - Copia\Valorant-External-main\x64\Release
		$a_01_1 = {72 61 73 66 64 74 79 61 73 64 61 73 2e 70 64 62 } //1 rasfdtyasdas.pdb
		$a_01_2 = {73 64 66 67 64 66 67 66 64 2e 70 64 62 } //1 sdfgdfgfd.pdb
		$a_01_3 = {69 61 73 75 69 64 6f 73 64 66 2e 70 64 62 } //1 iasuidosdf.pdb
		$a_01_4 = {69 6d 20 4d 45 53 54 45 52 65 73 70 20 66 69 6e 61 6c 20 74 65 73 74 61 72 20 63 6f 69 73 61 73 20 2d 20 43 6f 70 69 61 20 2d 20 43 6f 70 69 61 20 2d 20 43 6f 70 69 61 20 2d 20 43 6f 70 69 61 56 61 6c 6f 72 61 6e 74 20 2d 20 45 78 74 65 72 6e 61 6c 20 2d 20 6d 61 69 6e 56 61 6c 6f 72 61 6e 74 4f 70 74 69 6d 75 73 50 72 69 6e 63 65 70 73 2e 74 74 66 } //1 im MESTEResp final testar coisas - Copia - Copia - Copia - CopiaValorant - External - mainValorantOptimusPrinceps.ttf
		$a_01_5 = {5c 00 74 00 65 00 6d 00 70 00 6c 00 65 00 2e 00 72 00 61 00 72 00 } //1 \temple.rar
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}