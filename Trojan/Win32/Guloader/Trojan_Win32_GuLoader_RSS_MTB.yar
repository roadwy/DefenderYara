
rule Trojan_Win32_GuLoader_RSS_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RSS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {5c 46 61 67 69 6e 73 70 65 6b 74 72 65 72 6e 65 5c 61 66 66 75 67 74 5c 64 75 6e 74 65 72 } //1 \Faginspektrerne\affugt\dunter
		$a_81_1 = {5c 63 6f 6e 73 74 61 6e 63 79 2e 61 6e 73 } //1 \constancy.ans
		$a_81_2 = {4c 62 72 69 6b 6b 65 72 6e 65 73 34 36 2e 69 6e 69 } //1 Lbrikkernes46.ini
		$a_81_3 = {63 6c 61 78 6f 6e 20 72 65 6a 69 63 65 72 65 } //1 claxon rejicere
		$a_81_4 = {69 6d 70 75 67 6e 65 72 20 74 69 6b 61 6e 74 65 6e 73 20 6d 65 64 69 61 61 6e 61 6c 79 73 65 } //1 impugner tikantens mediaanalyse
		$a_81_5 = {6b 61 6d 6d 65 72 6a 75 6e 6b 65 72 6e 65 2e 65 78 65 } //1 kammerjunkerne.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}