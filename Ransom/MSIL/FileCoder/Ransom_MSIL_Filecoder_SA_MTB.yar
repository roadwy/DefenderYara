
rule Ransom_MSIL_Filecoder_SA_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {21 21 21 52 65 61 64 6d 65 21 21 21 48 65 6c 70 21 21 21 2e 74 78 74 } //1 !!!Readme!!!Help!!!.txt
		$a_81_1 = {64 61 74 61 31 39 39 32 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //1 data1992@protonmail.com
		$a_81_2 = {73 68 75 74 64 6f 77 6e 2e 65 78 65 } //1 shutdown.exe
		$a_81_3 = {74 61 73 6b 6b 69 6c 6c 2e 65 78 65 } //1 taskkill.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Ransom_MSIL_Filecoder_SA_MTB_2{
	meta:
		description = "Ransom:MSIL/Filecoder.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_03_0 = {11 09 11 0a 61 13 15 11 08 11 0f 11 15 20 90 01 04 5f 90 00 } //2
		$a_03_1 = {58 11 15 20 00 00 ff 00 5f 1f 10 64 d2 9c 11 08 11 0f 19 58 11 15 20 90 01 04 5f 1f 18 64 d2 90 00 } //2
		$a_01_2 = {55 31 4f 41 39 6f 57 4f 79 44 4a 61 75 69 34 48 38 6e } //1 U1OA9oWOyDJaui4H8n
		$a_01_3 = {78 50 33 4a 79 34 56 55 41 56 57 47 75 45 38 4b 6d 6f } //1 xP3Jy4VUAVWGuE8Kmo
		$a_01_4 = {54 50 49 6e 46 6e 34 66 45 38 70 41 4c 4e 38 71 39 6c 6f } //1 TPInFn4fE8pALN8q9lo
		$a_01_5 = {53 79 73 74 65 6d 2e 49 4f 2e 43 6f 6d 70 72 65 73 73 69 6f 6e } //1 System.IO.Compression
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}
rule Ransom_MSIL_Filecoder_SA_MTB_3{
	meta:
		description = "Ransom:MSIL/Filecoder.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {49 66 20 79 6f 75 20 77 61 6e 6e 61 20 73 75 70 70 6f 72 74 20 6d 65 2c 20 79 6f 75 20 63 61 6e 20 73 65 6e 64 20 6d 65 20 61 20 62 65 65 72 20 6d 6f 6e 65 79 20 76 69 61 20 63 72 79 70 74 6f 63 75 72 72 65 6e 63 79 2e 20 54 68 61 6e 6b 73 20 61 20 6c 6f 74 2e } //1 If you wanna support me, you can send me a beer money via cryptocurrency. Thanks a lot.
		$a_81_1 = {54 68 65 72 65 20 69 73 20 6e 6f 20 66 69 6c 65 21 } //1 There is no file!
		$a_81_2 = {46 69 6c 65 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 21 } //1 File has been encrypted!
		$a_81_3 = {50 6c 65 61 73 65 20 65 6e 74 65 72 20 31 20 62 79 74 65 20 6c 65 6e 67 74 20 70 61 73 73 77 6f 72 64 21 } //1 Please enter 1 byte lengt password!
		$a_81_4 = {44 6f 6e 74 20 62 6c 61 6e 6b 20 74 68 65 20 70 61 74 68 21 } //1 Dont blank the path!
		$a_81_5 = {4a 6f 6e 43 72 79 70 74 2e 70 64 62 } //1 JonCrypt.pdb
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}