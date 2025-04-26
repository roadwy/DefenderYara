
rule Trojan_BAT_Nanocore_ABCL_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABCL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 08 09 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 d2 06 28 ?? ?? ?? 06 00 00 09 1b 59 1c 58 0d 09 17 fe 04 13 09 11 09 2d c3 } //5
		$a_01_1 = {4d 00 79 00 47 00 61 00 6d 00 65 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 MyGame.Properties.Resources
		$a_01_2 = {41 00 65 00 65 00 65 00 65 00 } //1 Aeeee
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}