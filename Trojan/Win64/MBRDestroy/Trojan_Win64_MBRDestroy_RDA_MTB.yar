
rule Trojan_Win64_MBRDestroy_RDA_MTB{
	meta:
		description = "Trojan:Win64/MBRDestroy.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 8d 4c 24 40 48 c7 44 24 20 00 00 00 00 48 8b c8 48 8d 15 ?? ?? ?? ?? 41 b8 00 02 00 00 48 8b d8 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}