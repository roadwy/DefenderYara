
rule Trojan_BAT_AveMaria_NAV_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 20 00 01 00 00 6f ?? ?? 00 0a 06 20 ?? ?? 00 00 28 ?? ?? 00 06 28 ?? ?? 00 0a 6f ?? ?? 00 0a 06 20 ?? ?? 00 00 28 ?? ?? 00 06 28 ?? ?? 00 0a 6f ?? ?? 00 0a 06 06 6f ?? ?? 00 0a 06 6f ?? ?? 00 0a 6f ?? ?? 00 0a 0b 73 ?? ?? 00 0a 0c 08 07 17 73 ?? ?? 00 0a 0d 28 ?? ?? 00 06 13 04 09 11 04 16 11 04 8e 69 6f ?? ?? 00 0a 08 6f ?? ?? 00 0a } //5
		$a_01_1 = {4f 6b 6b 66 6e 76 78 64 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Okkfnvxd.Properties.Resources.resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}