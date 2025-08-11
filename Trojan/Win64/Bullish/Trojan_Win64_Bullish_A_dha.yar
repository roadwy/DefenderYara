
rule Trojan_Win64_Bullish_A_dha{
	meta:
		description = "Trojan:Win64/Bullish.A!dha,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {6d 73 6b 6d 64 6a 77 6f } //1 mskmdjwo
		$a_01_1 = {64 65 6a 66 6f 77 68 66 6a 77 6c 66 65 6b 6a 66 4a 4f 49 } //1 dejfowhfjwlfekjfJOI
		$a_01_2 = {64 6a 76 6f 32 6f 65 6a 66 32 } //1 djvo2oejf2
		$a_01_3 = {72 6f 6d 73 69 66 6c } //1 romsifl
		$a_01_4 = {70 6f 65 70 6f 66 6a 6f 77 } //1 poepofjow
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}