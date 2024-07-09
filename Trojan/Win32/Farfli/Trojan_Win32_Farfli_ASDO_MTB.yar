
rule Trojan_Win32_Farfli_ASDO_MTB{
	meta:
		description = "Trojan:Win32/Farfli.ASDO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {4a f9 05 cf 37 7b fa 1d ef f7 c0 34 ed ad 2f 01 88 ?? ?? ?? ?? 35 48 df a7 61 93 3b 09 } //5
		$a_01_1 = {1d 06 26 94 7d 27 ed 15 10 43 10 55 bd 67 5b 53 a5 ba 20 74 8c a0 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}