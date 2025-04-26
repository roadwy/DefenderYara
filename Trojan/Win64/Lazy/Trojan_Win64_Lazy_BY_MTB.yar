
rule Trojan_Win64_Lazy_BY_MTB{
	meta:
		description = "Trojan:Win64/Lazy.BY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 09 00 00 "
		
	strings :
		$a_01_0 = {41 44 53 69 73 67 66 69 6f 73 65 69 6a 67 65 73 67 } //1 ADSisgfioseijgesg
		$a_01_1 = {49 4f 68 6a 6f 69 73 61 64 6a 67 66 69 73 64 6a 67 65 73 69 67 } //1 IOhjoisadjgfisdjgesig
		$a_01_2 = {4b 4f 69 6f 73 61 65 64 69 6f 67 73 65 69 6f 6a 67 73 64 } //1 KOiosaediogseiojgsd
		$a_01_3 = {4d 6f 69 70 64 65 61 73 69 6f 67 73 61 65 64 69 6a 67 73 64 } //1 Moipdeasiogsaedijgsd
		$a_01_4 = {43 69 6f 61 6a 73 65 66 6f 69 65 61 66 69 6a 61 65 } //1 Cioajsefoieafijae
		$a_01_5 = {48 4e 61 66 69 61 6a 66 64 69 61 65 77 69 66 6a 61 65 6a 69 } //1 HNafiajfdiaewifjaeji
		$a_01_6 = {49 6a 69 73 61 6a 66 67 69 65 73 6a 66 69 6a 61 73 65 64 66 64 } //1 Ijisajfgiesjfijasedfd
		$a_01_7 = {4e 6f 69 61 69 66 6f 61 6a 69 66 73 61 69 6a 64 66 64 73 } //1 Noiaifoajifsaijdfds
		$a_01_8 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //2 WaitForSingleObject
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*2) >=6
 
}