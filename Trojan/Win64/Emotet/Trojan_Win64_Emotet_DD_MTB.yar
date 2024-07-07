
rule Trojan_Win64_Emotet_DD_MTB{
	meta:
		description = "Trojan:Win64/Emotet.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d0 8b c3 ff c3 8d 14 d2 03 d2 2b c2 48 63 d0 48 8b 05 90 02 04 8a 14 02 32 14 3e 88 17 48 ff c7 49 ff cf 75 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}