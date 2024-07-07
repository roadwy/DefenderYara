
rule Trojan_Win32_Mucc_AN_MTB{
	meta:
		description = "Trojan:Win32/Mucc.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 10 a7 38 08 00 2b 33 71 b5 aa 4b d3 a4 88 e3 0c 4a bd 18 fa d2 15 90 02 04 3d fb fc fa a0 68 10 a7 38 08 00 2b 33 71 b5 7b 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}