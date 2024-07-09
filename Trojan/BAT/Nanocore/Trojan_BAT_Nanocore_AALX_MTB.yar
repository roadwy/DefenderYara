
rule Trojan_BAT_Nanocore_AALX_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.AALX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 09 07 8e 69 5d 07 09 07 8e 69 5d 91 08 09 08 28 ?? 00 00 06 5d 28 ?? 00 00 06 61 28 ?? 00 00 06 07 09 17 58 07 8e 69 5d 91 28 ?? 00 00 06 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? 00 00 06 d2 9c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}