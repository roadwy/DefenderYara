
rule Trojan_BAT_Tedy_NBA_MTB{
	meta:
		description = "Trojan:BAT/Tedy.NBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {6f 26 00 00 0a 6f ?? 00 00 0a 0a 28 ?? 00 00 0a 04 28 ?? 00 00 06 16 1f 10 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 02 06 07 28 ?? 00 00 06 } //5
		$a_01_1 = {43 54 6f 6f 6c 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 CTools.Properties.Resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}