
rule Trojan_Win64_Zusy_ARAX_MTB{
	meta:
		description = "Trojan:Win64/Zusy.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 04 24 48 ff c0 48 89 04 24 48 8b 44 24 28 48 39 04 24 73 2e 0f b6 44 24 30 48 8b 0c 24 48 8b 54 24 08 48 03 d1 48 8b ca 0f b6 09 33 c8 8b c1 48 8b 0c 24 48 8b 54 24 08 48 03 d1 48 8b ca 88 01 eb bc } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}