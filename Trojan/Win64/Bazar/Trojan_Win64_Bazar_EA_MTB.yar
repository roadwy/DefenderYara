
rule Trojan_Win64_Bazar_EA_MTB{
	meta:
		description = "Trojan:Win64/Bazar.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 84 24 f8 00 00 00 b8 0a 00 00 00 48 01 f8 48 89 44 24 78 bd 03 00 00 00 48 89 c8 48 09 e8 48 89 84 24 f0 00 00 00 48 09 cb 48 89 c8 48 09 e8 48 89 84 24 e8 00 00 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}