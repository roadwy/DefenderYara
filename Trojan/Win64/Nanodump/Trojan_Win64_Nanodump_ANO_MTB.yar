
rule Trojan_Win64_Nanodump_ANO_MTB{
	meta:
		description = "Trojan:Win64/Nanodump.ANO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 45 a0 48 8b 45 a0 48 83 c0 05 48 89 45 98 48 8b 45 98 48 89 c1 e8 ?? ?? ?? ?? 48 89 45 e8 48 8b 4d b0 48 8b 55 98 48 8b 45 e8 49 89 c8 48 89 c1 48 8b 05 ?? ?? 00 00 ff d0 48 8b 55 98 48 8b 45 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}