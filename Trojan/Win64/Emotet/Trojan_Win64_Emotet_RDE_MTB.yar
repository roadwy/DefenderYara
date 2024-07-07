
rule Trojan_Win64_Emotet_RDE_MTB{
	meta:
		description = "Trojan:Win64/Emotet.RDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 0f b6 08 4d 8d 40 01 8b d0 2a c8 81 e2 ff 03 00 00 ff c0 42 32 0c 0a 41 88 48 ff 3b c7 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}