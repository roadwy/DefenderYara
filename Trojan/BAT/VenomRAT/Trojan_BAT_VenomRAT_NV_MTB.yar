
rule Trojan_BAT_VenomRAT_NV_MTB{
	meta:
		description = "Trojan:BAT/VenomRAT.NV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 1d dc 00 06 72 ?? 58 18 70 7e ?? 18 00 04 6f ?? 00 00 0a 0a 06 74 ?? 00 00 1b 0b 2b 00 } //4
		$a_01_1 = {6d 61 72 6b 65 74 70 6c 61 63 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 marketplace.Properties.Resources
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}