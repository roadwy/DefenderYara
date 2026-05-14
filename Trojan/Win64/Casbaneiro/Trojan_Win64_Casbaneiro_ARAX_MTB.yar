
rule Trojan_Win64_Casbaneiro_ARAX_MTB{
	meta:
		description = "Trojan:Win64/Casbaneiro.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 01 8b d0 33 d6 42 8d 34 00 81 e6 ff 00 00 80 7d 0a ff ce 81 ce 00 ff ff ff ff c6 88 11 48 ff c1 49 3b c9 72 d9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}