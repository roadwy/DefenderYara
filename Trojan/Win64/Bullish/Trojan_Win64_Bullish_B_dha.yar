
rule Trojan_Win64_Bullish_B_dha{
	meta:
		description = "Trojan:Win64/Bullish.B!dha,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 6b 77 68 6b 68 66 77 77 } //1 hkwhkhfww
		$a_01_1 = {68 66 77 65 68 6a 6b 77 68 65 66 71 } //1 hfwehjkwhefq
		$a_01_2 = {6a 4a 68 71 77 68 6a 68 64 71 } //1 jJhqwhjhdq
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}