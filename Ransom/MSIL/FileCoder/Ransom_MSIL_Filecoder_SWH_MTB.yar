
rule Ransom_MSIL_Filecoder_SWH_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.SWH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {45 6e 63 72 79 70 74 53 79 73 74 65 6d } //2 EncryptSystem
		$a_01_1 = {24 62 38 34 31 63 32 39 61 2d 66 32 64 33 2d 34 61 30 38 2d 62 62 38 30 2d 34 34 33 31 35 36 31 36 64 31 63 37 } //1 $b841c29a-f2d3-4a08-bb80-44315616d1c7
		$a_01_2 = {45 6e 74 65 72 6e 61 6c 52 65 64 5c 6f 62 6a 5c 44 65 62 75 67 5c 4a 50 47 2d 44 61 74 65 69 2e 70 64 62 } //1 EnternalRed\obj\Debug\JPG-Datei.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}
rule Ransom_MSIL_Filecoder_SWH_MTB_2{
	meta:
		description = "Ransom:MSIL/Filecoder.SWH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 06 72 2d 01 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 26 72 51 01 00 70 28 ?? 00 00 0a 26 72 51 01 00 70 17 28 ?? 00 00 0a 00 06 72 2d 01 00 70 28 ?? 00 00 0a 17 28 ?? 00 00 0a 00 08 72 c7 01 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 00 73 87 00 00 0a 13 05 11 05 72 01 02 00 70 6f ?? 00 00 0a 00 11 05 17 6f ?? 00 00 0a 00 11 05 72 11 02 00 70 08 72 a3 02 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 05 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}