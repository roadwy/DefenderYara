
rule Trojan_Win64_Dukes_MA_MTB{
	meta:
		description = "Trojan:Win64/Dukes.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {99 f7 f9 88 d0 88 44 24 07 48 8b 44 24 08 0f b7 4c 24 04 8a 04 08 88 44 24 03 48 8b 44 24 08 0f b6 4c 24 07 8a 14 08 48 8b 44 24 08 0f b7 4c 24 04 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}