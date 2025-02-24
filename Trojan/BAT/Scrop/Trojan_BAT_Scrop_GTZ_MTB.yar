
rule Trojan_BAT_Scrop_GTZ_MTB{
	meta:
		description = "Trojan:BAT/Scrop.GTZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_03_0 = {06 17 1a 6f ?? ?? ?? 0a 0b 07 1f 3c 5a 1f 3c 5a 20 e8 03 00 00 5a 0c 08 28 ?? ?? ?? 0a 00 00 17 0d 2b d6 } //10
		$a_03_1 = {06 17 1a 6f ?? ?? ?? 0a 0c 08 1f 3c 5a 1f 3c 5a 20 e8 03 00 00 5a 0d 09 28 ?? ?? ?? 0a 00 00 00 17 13 04 2b c7 } //10
		$a_03_2 = {06 17 1a 6f ?? ?? ?? 0a 0b 07 1f 3c 5a 1f 3c 5a 20 e8 03 00 00 5a 0c 20 60 ea 00 00 28 ?? ?? ?? 0a 00 00 17 0d 2b d2 } //10
		$a_80_3 = {75 73 65 72 69 6e 66 6f 2e 74 78 74 } //userinfo.txt  1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*10+(#a_80_3  & 1)*1) >=11
 
}