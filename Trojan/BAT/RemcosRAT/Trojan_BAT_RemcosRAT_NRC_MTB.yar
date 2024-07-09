
rule Trojan_BAT_RemcosRAT_NRC_MTB{
	meta:
		description = "Trojan:BAT/RemcosRAT.NRC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 e5 00 00 0a 80 ?? ?? ?? 04 11 04 20 ?? ?? ?? 76 5a 20 ?? ?? ?? a0 61 38 ?? ?? ?? ff 00 11 04 20 ?? ?? ?? 6f 5a 20 ?? ?? ?? 9e 61 38 ?? ?? ?? ff 11 04 20 ?? ?? ?? 88 5a 20 ?? ?? ?? 4d 61 } //5
		$a_01_1 = {52 61 6e 64 6f 6d 4d 61 6b 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 RandomMaker.Properties.Resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}