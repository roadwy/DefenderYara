
rule Trojan_Win64_IcedID_MAT_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {79 70 6f 6c 79 74 72 65 77 } //1 ypolytrew
		$a_01_1 = {42 49 62 70 65 34 73 57 49 4d 30 61 } //1 BIbpe4sWIM0a
		$a_01_2 = {43 67 39 67 36 69 68 72 73 78 31 65 } //1 Cg9g6ihrsx1e
		$a_01_3 = {4c 58 42 42 68 6b 45 61 73 58 59 59 49 46 5a 62 } //1 LXBBhkEasXYYIFZb
		$a_01_4 = {4d 76 61 52 35 46 42 54 59 63 54 35 34 77 4d } //1 MvaR5FBTYcT54wM
		$a_01_5 = {52 72 70 42 4d 74 74 61 70 67 75 47 71 45 36 } //1 RrpBMttapguGqE6
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}