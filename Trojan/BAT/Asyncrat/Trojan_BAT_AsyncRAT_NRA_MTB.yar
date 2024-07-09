
rule Trojan_BAT_AsyncRAT_NRA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.NRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {7e 59 00 00 04 06 7e ?? ?? 00 04 06 91 20 ?? ?? 00 00 59 d2 9c 00 06 17 58 0a 06 7e ?? ?? 00 04 8e 69 fe 04 0b 07 2d d7 } //5
		$a_01_1 = {4b 61 6e 68 61 6c 2e 50 72 6f 70 65 72 74 69 65 73 } //1 Kanhal.Properties
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}