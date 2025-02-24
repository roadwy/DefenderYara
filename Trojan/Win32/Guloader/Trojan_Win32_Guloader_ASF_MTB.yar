
rule Trojan_Win32_Guloader_ASF_MTB{
	meta:
		description = "Trojan:Win32/Guloader.ASF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 "
		
	strings :
		$a_01_0 = {52 61 6d 74 69 6c 73 5c 46 6f 72 6d 61 6c 64 65 68 79 64 73 5c 74 79 6e 67 64 65 70 75 6e 6b 74 65 72 6e 65 } //2 Ramtils\Formaldehyds\tyngdepunkterne
		$a_01_1 = {62 72 75 64 73 69 6b 72 65 73 74 65 2e 74 78 74 } //2 brudsikreste.txt
		$a_01_2 = {61 72 72 6f 67 61 6e 74 6c 79 2e 77 65 61 } //1 arrogantly.wea
		$a_01_3 = {76 61 67 61 62 6f 6e 64 61 67 65 2e 66 69 73 } //1 vagabondage.fis
		$a_01_4 = {6b 72 65 64 69 74 64 61 67 65 5c 79 69 65 6c 64 65 6e } //1 kreditdage\yielden
		$a_01_5 = {48 65 74 65 72 6f 73 63 69 61 6e 32 33 34 25 5c 73 61 6d 6d 65 6e 74 72 61 61 64 74 65 5c 6b 65 72 73 65 79 6d 65 72 65 } //1 Heteroscian234%\sammentraadte\kerseymere
		$a_01_6 = {62 61 64 6d 69 74 6f 6e 73 5c 67 61 72 61 6e 74 69 73 65 64 6c 65 72 6e 65 2e 62 65 6b } //1 badmitons\garantisedlerne.bek
		$a_01_7 = {76 61 6e 73 6b 62 6e 65 72 6e 65 25 5c 73 70 72 6f 67 6b 6c 66 74 73 5c 50 68 6f 74 6f 63 6f 6d 70 6f 73 65 73 2e 63 6f 6e } //1 vanskbnerne%\sprogklfts\Photocomposes.con
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=10
 
}