
rule Trojan_Win32_GuLoader_RSI_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RSI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {53 6f 66 74 77 61 72 65 5c 53 68 72 69 6c 6c 69 6e 67 32 32 31 5c 6d 65 6c 61 6e 65 6d 69 61 } //1 Software\Shrilling221\melanemia
		$a_81_1 = {39 39 5c 44 6b 76 69 6e 67 65 72 6e 65 73 38 38 5c 6d 61 6c 61 67 61 } //1 99\Dkvingernes88\malaga
		$a_81_2 = {23 5c 61 66 73 69 6e 64 69 67 73 74 65 73 5c 70 68 79 73 69 74 68 65 69 73 6d 5c 61 6c 74 69 6e 67 73 6d 65 64 6c 65 6d 6d 65 74 } //1 #\afsindigstes\physitheism\altingsmedlemmet
		$a_81_3 = {69 6e 64 65 66 65 6e 73 69 62 6c 79 5c 61 6e 74 69 61 74 6f 6d 6b 61 6d 70 61 67 6e 65 6e } //1 indefensibly\antiatomkampagnen
		$a_81_4 = {4c 65 76 6e 65 64 73 6d 69 64 64 65 6c 65 74 2e 68 79 64 } //1 Levnedsmiddelet.hyd
		$a_81_5 = {76 65 6a 6e 69 6e 67 65 72 73 2e 6a 70 67 } //1 vejningers.jpg
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}