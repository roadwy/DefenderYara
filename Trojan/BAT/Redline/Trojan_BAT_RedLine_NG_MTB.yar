
rule Trojan_BAT_RedLine_NG_MTB{
	meta:
		description = "Trojan:BAT/RedLine.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 00 00 28 ?? 00 00 0a 28 ?? 00 00 0a 25 7e ?? 00 00 04 61 20 ?? 00 00 00 59 20 ?? 00 00 00 fe ?? ?? 00 5a 58 fe ?? ?? 00 } //5
		$a_01_1 = {61 6e 69 6d 61 74 69 6f 6e 2e 52 65 6e 64 65 72 4e 6f 64 65 41 6e 69 6d 61 74 6f 72 2e 6d 6f 64 75 6c 65 31 32 } //1 animation.RenderNodeAnimator.module12
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}