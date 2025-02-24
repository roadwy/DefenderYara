
rule Trojan_Win64_Ulise_ARAZ_MTB{
	meta:
		description = "Trojan:Win64/Ulise.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 e9 55 f7 e9 c1 fa 03 8b c2 c1 e8 1f 03 d0 6b d2 1a 2b ca 80 c1 61 41 88 09 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}