
rule Trojan_Win64_Filecoder_SCR_MTB{
	meta:
		description = "Trojan:Win64/Filecoder.SCR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 c9 49 89 e9 c4 e1 f9 6e c8 48 8b 84 24 10 04 00 00 4c 8d 05 c3 02 00 00 c4 e3 f1 22 84 24 08 04 00 00 01 48 89 45 10 c5 fa 7f 45 00 48 c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 00 ff 15 90 ab 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}