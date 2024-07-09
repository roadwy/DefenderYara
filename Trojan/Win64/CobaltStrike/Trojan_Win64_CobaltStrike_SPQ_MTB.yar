
rule Trojan_Win64_CobaltStrike_SPQ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 db ba 07 00 00 00 48 8b 0d ?? ?? ?? ?? ff 15 ?? ?? ?? ?? ff c3 81 fb 7b 03 00 00 72 e4 80 34 3e 05 ba 07 00 00 00 48 8b 0d ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 ff c6 48 81 fe 7b 03 00 00 72 } //2
		$a_03_1 = {ba 7b 03 00 00 33 c9 44 8d 49 40 41 b8 00 10 00 00 ff 15 ?? ?? ?? ?? 48 8b d8 48 85 c0 75 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}