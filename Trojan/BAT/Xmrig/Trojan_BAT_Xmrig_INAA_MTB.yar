
rule Trojan_BAT_Xmrig_INAA_MTB{
	meta:
		description = "Trojan:BAT/Xmrig.INAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8e 69 5d 1f 09 58 1f 0c 58 1f 15 59 1b 58 1b 59 91 61 ?? 06 1a 58 4a 20 0e 02 00 00 58 20 0d 02 00 00 59 ?? 8e 69 5d 1f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}