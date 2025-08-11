
rule Trojan_BAT_DarkCloud_GTD_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.GTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 00 07 03 6f ?? 00 00 0a 00 07 04 6f ?? 00 00 0a 00 07 17 6f ?? 00 00 0a 00 07 18 6f ?? 00 00 0a 00 73 ?? ?? ?? ?? 0c 08 07 6f ?? 00 00 0a 17 73 ?? ?? ?? ?? 0d 00 09 06 16 06 8e 69 6f ?? 00 00 0a 00 09 6f ?? 00 00 0a 00 08 6f ?? 00 00 0a 13 04 de 28 } //10
		$a_01_1 = {43 6f 6e 66 75 73 65 72 2e 43 6f 72 65 } //1 Confuser.Core
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}