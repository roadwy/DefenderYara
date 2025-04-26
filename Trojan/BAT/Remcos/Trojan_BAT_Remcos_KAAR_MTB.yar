
rule Trojan_BAT_Remcos_KAAR_MTB{
	meta:
		description = "Trojan:BAT/Remcos.KAAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 16 5d 91 13 ?? 11 ?? 11 ?? 91 11 ?? 61 13 ?? 11 ?? 17 58 11 ?? 5d 13 ?? 11 ?? 11 ?? 91 13 ?? 11 ?? 11 ?? 59 13 0e 20 ff 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}