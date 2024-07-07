
rule Trojan_BAT_FormBook_AFB_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0c 07 11 0b 91 59 11 0d 58 11 0d 5d 13 0e 07 11 09 11 0e d2 9c 11 11 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_AFB_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 13 05 11 05 28 90 01 03 06 13 06 07 06 11 06 d2 9c 00 11 04 17 58 90 00 } //2
		$a_01_1 = {53 00 6b 00 79 00 } //1 Sky
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_FormBook_AFB_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0b 16 0c 2b 15 00 06 08 03 08 91 07 08 07 8e 69 5d 91 61 d2 9c 00 08 17 58 0c 08 04 8e 69 fe 04 0d 09 2d e1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_AFB_MTB_4{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {91 61 07 11 07 20 c0 e1 00 00 5d 91 20 00 01 00 00 58 20 00 01 00 00 5d 59 d2 9c 06 17 58 0a 06 20 c0 e1 00 00 fe 04 13 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_AFB_MTB_5{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 04 16 2d f8 2b 19 11 04 1e 25 2c e1 62 13 04 11 04 06 07 25 17 59 0b 91 58 13 04 09 17 59 0d 18 39 78 00 00 00 09 2d de } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_AFB_MTB_6{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 05 2b 46 00 07 11 05 07 8e 69 5d 07 11 05 07 8e 69 5d 91 08 11 05 1f 16 5d 91 61 28 90 01 01 00 00 0a 07 11 05 17 58 07 8e 69 5d 91 28 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_AFB_MTB_7{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 09 07 8e 69 5d 02 07 09 07 8e 69 5d 91 08 09 08 6f 90 01 01 00 00 0a 5d 6f 90 01 01 00 00 0a 61 28 90 01 01 00 00 0a 07 09 17 58 07 8e 69 5d 91 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_AFB_MTB_8{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 18 6f 90 01 03 0a 00 06 18 6f 90 01 03 0a 00 06 02 7b 04 00 00 04 6f 90 01 03 0a 00 06 6f 90 01 03 0a 0b 07 03 16 03 8e 69 6f 90 01 03 0a 0c 08 0d de 0b 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_AFB_MTB_9{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 2b 3a 06 09 5d 13 05 06 17 58 09 5d 13 0a 07 11 0a 91 90 01 05 58 13 0b 07 11 05 91 13 0c 07 11 05 11 0c 11 06 06 1f 16 5d 91 61 11 0b 59 90 01 05 5d d2 9c 06 17 58 0a 06 09 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_AFB_MTB_10{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0b 2b 3a 06 07 06 8e 69 5d 06 07 06 8e 69 5d 91 11 04 07 1f 16 5d 91 61 06 07 17 58 06 8e 69 5d 91 28 90 01 01 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 90 01 01 00 00 0a 9c 07 17 58 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_AFB_MTB_11{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 05 16 8c 90 01 01 00 00 01 19 8d 90 01 01 00 00 01 25 16 08 16 9a a2 25 17 08 17 9a a2 25 18 20 93 c8 2a 2a 28 90 01 01 00 00 2b a2 13 0f 11 0f 28 90 00 } //2
		$a_01_1 = {74 68 69 6e 6b 67 65 61 72 5f 66 6f 72 6d } //1 thinkgear_form
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_FormBook_AFB_MTB_12{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 06 2b 3d 00 09 11 06 11 05 6f 90 01 01 00 00 0a 17 59 2e 18 11 05 11 06 6f 90 01 01 00 00 0a 08 11 06 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 2b 09 11 05 11 06 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 26 00 11 06 17 58 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_AFB_MTB_13{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 11 08 91 13 0b 20 00 01 00 00 13 0c 11 0b 08 11 09 91 61 07 11 0a 91 59 11 0c 58 11 0c 5d 13 0d 07 11 08 11 0d d2 9c 00 11 07 17 58 13 07 } //2
		$a_01_1 = {51 75 61 6e 4c 79 54 68 75 56 69 65 6e 2e 51 75 61 6e 4c 79 54 68 61 6e 68 56 69 65 6e } //1 QuanLyThuVien.QuanLyThanhVien
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_FormBook_AFB_MTB_14{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 0a 2b 59 00 20 00 01 00 00 13 0b 11 0a 17 58 13 0c 11 0a 20 00 56 01 00 5d 13 0d 11 0c 20 00 56 01 00 5d 13 0e 11 04 11 0e 91 11 0b 58 13 0f 11 04 11 0d 91 13 10 11 05 11 0a 1f 16 5d 91 13 11 11 10 11 11 61 13 12 11 04 11 0d 11 12 11 0f 59 11 0b 5d d2 9c 00 11 0a 17 58 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_AFB_MTB_15{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 14 14 19 8d 90 01 03 01 25 16 06 6f 90 01 03 0a a2 25 17 16 8c 90 01 03 01 a2 25 18 06 6f 90 00 } //1
		$a_03_1 = {0a 16 0b 02 6f 90 01 01 00 00 0a 17 59 0c 2b 18 00 06 07 93 0d 06 07 06 08 93 9d 06 08 09 9d 07 17 58 0b 08 17 59 0c 00 07 08 fe 04 13 04 11 04 2d de 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_BAT_FormBook_AFB_MTB_16{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6c 69 73 74 61 41 6d 69 7a 61 64 65 73 } //1 listaAmizades
		$a_01_1 = {47 72 61 76 61 72 41 6d 69 7a 61 64 65 73 } //1 GravarAmizades
		$a_01_2 = {47 65 72 61 72 41 72 71 75 69 76 6f 4d 61 74 63 68 41 6d 69 7a 61 64 65 73 } //1 GerarArquivoMatchAmizades
		$a_01_3 = {54 72 61 74 61 72 45 78 63 65 63 61 6f 41 72 71 75 69 76 6f } //1 TratarExcecaoArquivo
		$a_01_4 = {41 6d 69 67 6f 53 65 63 72 65 74 6f 57 69 6e 46 6f 72 6d 73 } //1 AmigoSecretoWinForms
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_BAT_FormBook_AFB_MTB_17{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0d 09 2c 5b 00 02 7b 90 01 01 00 00 04 08 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 13 04 11 04 2c 22 00 02 7b 90 01 01 00 00 04 08 6f 90 01 01 00 00 0a 16 90 00 } //1
		$a_03_1 = {0a 0c 2b 33 12 02 28 90 01 01 00 00 0a 0d 00 02 7b 90 01 01 00 00 04 6f 90 01 01 00 00 0a 09 6f 90 01 01 00 00 0a 73 90 01 01 00 00 0a 25 09 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 6f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_BAT_FormBook_AFB_MTB_18{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 00 6f 00 72 00 64 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 6f 00 72 00 43 00 68 00 61 00 6d 00 62 00 65 00 72 00 6c 00 69 00 6e 00 20 00 31 00 39 00 39 00 34 00 } //2 WordProcessorChamberlin 1994
		$a_01_1 = {41 00 6e 00 64 00 72 00 65 00 77 00 73 00 79 00 20 00 4c 00 69 00 62 00 } //2 Andrewsy Lib
		$a_01_2 = {36 32 36 30 30 63 36 63 2d 32 62 33 63 2d 34 62 64 62 2d 38 38 34 37 2d 38 39 62 61 37 32 39 64 35 39 37 34 } //2 62600c6c-2b3c-4bdb-8847-89ba729d5974
		$a_01_3 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
		$a_01_4 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d } //1 GetManifestResourceStream
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}