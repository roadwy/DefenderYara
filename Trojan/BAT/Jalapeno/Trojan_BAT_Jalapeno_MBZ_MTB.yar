
rule Trojan_BAT_Jalapeno_MBZ_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.MBZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 07 8e 69 5d 91 61 d2 81 ?? ?? 00 01 11 08 17 58 13 08 11 08 11 06 8e 69 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}