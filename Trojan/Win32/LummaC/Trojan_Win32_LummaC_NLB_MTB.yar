
rule Trojan_Win32_LummaC_NLB_MTB{
	meta:
		description = "Trojan:Win32/LummaC.NLB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_81_0 = {5f 63 72 79 70 74 65 64 2e 64 6c 6c } //2 _crypted.dll
		$a_81_1 = {40 62 6d 6e 76 69 64 6a 61 70 6d 75 71 76 71 6c 69 76 78 61 7a 69 72 63 70 70 62 6a 6f 6d 75 6e 6d 78 70 6a 79 65 69 77 75 62 74 70 68 6e 6d 68 65 6e 64 62 6a 78 79 6c 6f 79 61 72 62 63 68 } //1 @bmnvidjapmuqvqlivxazircppbjomunmxpjyeiwubtphnmhendbjxyloyarbch
		$a_81_2 = {70 74 6b 69 6f 75 75 65 63 6e 78 62 7a 71 68 77 66 74 79 6e 6b 76 6f 6b 70 77 6c 69 61 69 70 73 62 6a 79 73 62 67 68 6a 70 70 71 69 6b 62 71 74 6d 6e 68 65 74 } //1 ptkiouuecnxbzqhwftynkvokpwliaipsbjysbghjppqikbqtmnhet
		$a_81_3 = {78 62 66 79 69 62 63 7a 79 69 7a 68 73 69 77 69 67 78 73 68 64 6f 6a 75 6c 7a 63 66 6a 6e 76 6f 61 6b 67 76 68 67 73 } //1 xbfyibczyizhsiwigxshdojulzcfjnvoakgvhgs
		$a_81_4 = {6c 61 71 78 6b 71 63 70 66 79 76 70 61 6b 6d 6f 79 63 74 61 69 77 62 61 74 61 74 73 73 61 79 6c 6c 64 68 76 72 62 63 68 72 61 6e 68 71 } //1 laqxkqcpfyvpakmoyctaiwbatatssaylldhvrbchranhq
		$a_81_5 = {6f 63 64 78 6c 6f 6e 72 68 74 6f 62 78 7a 62 6d 6d 70 70 73 6b 74 6e 63 66 76 62 71 68 65 71 76 6d 75 65 6a 70 67 6f } //1 ocdxlonrhtobxzbmmppsktncfvbqheqvmuejpgo
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=7
 
}