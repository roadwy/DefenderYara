
rule Trojan_Win64_Emotet_DN_MTB{
	meta:
		description = "Trojan:Win64/Emotet.DN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {4d 8d 40 01 f7 e6 8b c6 ff c6 c1 ea 05 8d 0c 52 c1 e1 04 2b c1 48 63 c8 42 0f b6 04 11 43 32 44 07 ff 41 88 40 ff 41 3b f4 72 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}