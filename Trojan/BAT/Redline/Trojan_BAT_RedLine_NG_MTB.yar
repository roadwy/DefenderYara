
rule Trojan_BAT_RedLine_NG_MTB{
	meta:
		description = "Trojan:BAT/RedLine.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {fe 0c 00 00 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 25 7e 90 01 01 00 00 04 61 20 90 01 01 00 00 00 59 20 90 01 01 00 00 00 fe 90 01 02 00 5a 58 fe 90 01 02 00 90 00 } //01 00 
		$a_01_1 = {61 6e 69 6d 61 74 69 6f 6e 2e 52 65 6e 64 65 72 4e 6f 64 65 41 6e 69 6d 61 74 6f 72 2e 6d 6f 64 75 6c 65 31 32 } //00 00  animation.RenderNodeAnimator.module12
	condition:
		any of ($a_*)
 
}