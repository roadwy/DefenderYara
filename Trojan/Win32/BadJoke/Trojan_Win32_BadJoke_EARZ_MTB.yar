
rule Trojan_Win32_BadJoke_EARZ_MTB{
	meta:
		description = "Trojan:Win32/BadJoke.EARZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c2 83 c2 02 d3 e8 32 c1 88 84 0d 78 56 fc ff 41 81 fa 38 53 07 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win32_BadJoke_EARZ_MTB_2{
	meta:
		description = "Trojan:Win32/BadJoke.EARZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b d0 8b c8 c1 e9 08 0a c8 c1 ea 09 0a d0 02 d1 8b c8 c1 e9 07 0a c8 02 d1 8b c8 c1 e9 06 22 c8 02 d1 88 94 05 f8 59 f1 ff 40 3d 00 a6 0e 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}