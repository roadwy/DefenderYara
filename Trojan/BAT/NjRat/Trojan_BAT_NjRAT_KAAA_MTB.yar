
rule Trojan_BAT_NjRAT_KAAA_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.KAAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d 91 04 8e 69 5d 91 28 ?? 00 00 06 61 04 07 07 1d 5d d6 04 8e 69 5d 04 8e 69 5d 91 61 9c 07 17 d6 0b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}