
rule Trojan_BAT_Heracles_GXH_MTB{
	meta:
		description = "Trojan:BAT/Heracles.GXH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {26 00 08 7b ?? 00 00 04 16 fe 03 13 27 11 27 39 22 00 00 00 00 00 08 7b ?? 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a } //10
		$a_80_1 = {47 65 74 44 65 6c 65 67 61 74 65 46 6f 72 46 75 6e 63 74 69 6f 6e 50 6f 69 6e 74 65 72 } //GetDelegateForFunctionPointer  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}