
rule Trojan_Win32_BadJoke_RDA_MTB{
	meta:
		description = "Trojan:Win32/BadJoke.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 e0 0d 33 c2 8b c8 c1 e9 11 33 c8 8b f9 c1 e7 05 33 f9 8b c7 c1 e0 0d 33 c7 8b c8 c1 e9 11 33 c8 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}