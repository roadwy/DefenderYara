
rule Trojan_Win32_Guloader_LWG_MTB{
	meta:
		description = "Trojan:Win32/Guloader.LWG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {43 6f 65 6c 74 65 72 61 2e 65 6e 68 } //1 Coeltera.enh
		$a_81_1 = {66 65 6d 74 65 6e 61 61 72 73 66 64 73 65 6c 73 64 61 67 65 73 2e 74 78 74 } //1 femtenaarsfdselsdages.txt
		$a_81_2 = {67 6f 6f 73 65 73 6b 69 6e 2e 74 72 61 } //1 gooseskin.tra
		$a_81_3 = {42 72 73 6d 61 74 61 64 6f 72 31 31 33 2e 64 65 6e } //1 Brsmatador113.den
		$a_81_4 = {66 72 65 69 6c 65 76 20 62 6e 64 65 72 67 61 61 72 64 65 6e 65 2e 65 78 65 } //1 freilev bndergaardene.exe
		$a_81_5 = {6d 61 6b 61 72 6f 6e 69 65 72 73 20 70 6f 73 65 72 65 } //1 makaroniers posere
		$a_81_6 = {6e 6f 6e 61 6c 69 65 6e 61 74 69 6f 6e 20 62 61 6c 64 6f 72 20 73 65 6d 69 63 79 6c 69 6e 64 72 69 63 } //1 nonalienation baldor semicylindric
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}