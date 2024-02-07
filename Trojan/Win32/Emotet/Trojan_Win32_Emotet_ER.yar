
rule Trojan_Win32_Emotet_ER{
	meta:
		description = "Trojan:Win32/Emotet.ER,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 61 74 68 65 72 38 64 65 73 69 72 65 79 75 73 65 72 66 61 6c 6c 62 61 63 6b 43 68 72 6f 6d 69 75 6d 6d 65 6e 75 6d 65 6d 62 65 72 4f 6d 6e 69 62 6f 78 } //01 00  rather8desireyuserfallbackChromiummenumemberOmnibox
		$a_01_1 = {49 6d 74 65 23 25 66 55 35 61 7a 2d 68 64 3e 2a 2f 76 47 6b } //00 00  Imte#%fU5az-hd>*/vGk
	condition:
		any of ($a_*)
 
}