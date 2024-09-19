
rule Trojan_Win64_Rozena_BAO_MTB{
	meta:
		description = "Trojan:Win64/Rozena.BAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 48 8b 55 ?? 48 01 d0 0f b6 00 8b 55 fc 48 8b 4d ?? 48 01 ca 32 45 ?? 88 02 83 45 fc 01 8b 45 fc 3b 45 ?? 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}