
rule Trojan_BAT_Tedy_NED_MTB{
	meta:
		description = "Trojan:BAT/Tedy.NED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 6f ?? 00 00 0a 72 ?? 00 00 70 6f ?? 00 00 0a 0c 08 2d 4b 00 72 ?? 00 00 70 72 ?? 00 00 70 1a 1f 20 28 ?? 00 00 0a 1c fe 01 16 fe 01 0c 08 } //5
		$a_01_1 = {55 70 64 61 74 65 44 65 6d 6f 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 UpdateDemo.Properties.Resources.resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}