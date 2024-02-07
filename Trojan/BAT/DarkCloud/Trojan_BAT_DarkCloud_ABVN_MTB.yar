
rule Trojan_BAT_DarkCloud_ABVN_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.ABVN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 02 16 02 8e 69 6f 90 01 02 00 0a 0a 2b 00 06 2a 90 0a 19 00 7e 90 01 01 00 00 04 6f 90 00 } //01 00 
		$a_01_1 = {42 00 65 00 69 00 6a 00 69 00 6e 00 67 00 4a 00 69 00 6e 00 4a 00 69 00 6e 00 67 00 5a 00 68 00 65 00 6e 00 67 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00  BeijingJinJingZheng.Properties.Resources
	condition:
		any of ($a_*)
 
}