
rule Trojan_BAT_Xmrig_AXM_MTB{
	meta:
		description = "Trojan:BAT/Xmrig.AXM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 11 00 00 06 0a 28 02 00 00 0a 06 6f 03 00 00 0a 28 04 00 00 0a 28 03 00 00 06 0b dd 03 00 00 00 26 de db 07 2a } //2
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}