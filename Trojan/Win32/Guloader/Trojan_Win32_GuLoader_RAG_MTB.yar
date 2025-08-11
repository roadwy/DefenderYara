
rule Trojan_Win32_GuLoader_RAG_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {62 65 73 6b 79 74 74 65 6c 73 65 73 76 72 64 69 67 65 20 6b 61 72 6c 65 } //1 beskyttelsesvrdige karle
		$a_81_1 = {70 72 6f 72 65 6b 74 6f 72 65 72 73 20 64 65 73 63 65 6e 64 65 6e 74 20 6e 6f 6e 63 61 73 75 69 73 74 69 63 61 6c 6c 79 } //1 prorektorers descendent noncasuistically
		$a_81_2 = {73 79 6c 6e 6e 65 6e 20 61 66 74 72 6b 6e 69 6e 67 65 6e 73 20 64 69 7a 6f 72 67 61 6e 69 73 61 74 69 6f 6e } //1 sylnnen aftrkningens dizorganisation
		$a_81_3 = {62 72 6f 64 65 72 70 61 72 72 65 6e 65 2e 65 78 65 } //1 broderparrene.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}