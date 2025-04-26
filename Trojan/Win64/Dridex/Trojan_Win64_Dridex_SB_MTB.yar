
rule Trojan_Win64_Dridex_SB_MTB{
	meta:
		description = "Trojan:Win64/Dridex.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 "
		
	strings :
		$a_80_0 = {72 6d 69 23 64 52 66 2e 70 64 62 } //rmi#dRf.pdb  3
		$a_80_1 = {6a 32 39 2c 47 6f 6f 67 6c 65 73 35 45 6a 50 68 } //j29,Googles5EjPh  3
		$a_80_2 = {76 6b 67 42 69 67 67 65 72 78 76 65 72 73 69 6f 6e } //vkgBiggerxversion  3
		$a_80_3 = {50 67 49 46 61 63 65 62 6f 6f 6b 2c 63 6f 6e 74 61 69 6e 65 72 73 77 68 65 6e 4e 69 6e 74 65 72 72 75 70 74 51 6f 76 65 72 } //PgIFacebook,containerswhenNinterruptQover  3
		$a_80_4 = {59 61 75 74 6f 2d 75 70 64 61 74 65 35 } //Yauto-update5  3
		$a_80_5 = {50 73 63 73 63 72 69 70 74 65 64 32 33 2e 39 38 6e } //Pscscripted23.98n  3
		$a_80_6 = {34 2e 30 4e 6d 5a 62 72 6f 77 73 65 72 73 74 } //4.0NmZbrowserst  3
		$a_80_7 = {63 6f 75 6c 64 32 65 42 75 67 73 4b 64 65 76 65 6c 6f 70 65 72 73 2c 7a 39 } //could2eBugsKdevelopers,z9  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3) >=24
 
}
rule Trojan_Win64_Dridex_SB_MTB_2{
	meta:
		description = "Trojan:Win64/Dridex.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 "
		
	strings :
		$a_80_0 = {72 6d 69 23 64 52 66 2e 70 64 62 } //rmi#dRf.pdb  3
		$a_80_1 = {67 37 4b 74 68 65 61 5a 4c 74 68 65 } //g7KtheaZLthe  3
		$a_80_2 = {71 7a 73 6f 68 65 61 74 68 65 72 64 65 66 61 75 6c 74 2e 74 68 61 6e 68 61 74 61 6b 65 } //qzsoheatherdefault.thanhatake  3
		$a_80_3 = {76 6f 79 61 67 65 72 71 52 74 6f 57 73 } //voyagerqRtoWs  3
		$a_80_4 = {43 68 72 6f 6d 65 65 78 70 6c 61 69 6e 65 64 4d 4e 79 69 63 65 6d 61 6e 72 65 6c 69 65 64 73 75 6e 73 68 69 6e 65 } //ChromeexplainedMNyicemanreliedsunshine  3
		$a_80_5 = {62 75 69 6c 64 61 62 6c 65 79 54 } //buildableyT  3
		$a_80_6 = {61 6c 6c 50 75 62 6c 69 63 2c 31 32 33 34 35 41 64 61 6c 6c 61 73 } //allPublic,12345Adallas  3
		$a_80_7 = {6c 70 72 6f 74 6f 63 6f 6c 74 72 61 6e 73 6c 61 74 69 6f 6e 6c } //lprotocoltranslationl  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3) >=24
 
}