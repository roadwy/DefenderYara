
rule Trojan_Win64_Remcos_AKRE_MTB{
	meta:
		description = "Trojan:Win64/Remcos.AKRE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 8d 05 ed d7 07 00 b2 34 48 8d 4d d7 e8 ?? ?? ?? ?? 48 8d 0d 13 37 09 00 e8 ?? ?? ?? ?? 48 8d 0d 07 37 09 00 48 8b f0 e8 ?? ?? ?? ?? 4c 8d 45 97 48 8b f8 48 8d 15 d1 d7 07 00 48 8d 4d f7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}