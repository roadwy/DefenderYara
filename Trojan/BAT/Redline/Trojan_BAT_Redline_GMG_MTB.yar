
rule Trojan_BAT_Redline_GMG_MTB{
	meta:
		description = "Trojan:BAT/Redline.GMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? ?? 06 03 08 1b 58 1b 59 17 58 03 8e 69 5d 91 59 20 ?? ?? ?? ?? 58 1c 58 20 ?? ?? ?? ?? 5d d2 9c 08 } //10
		$a_01_1 = {61 48 52 30 63 44 70 6b 62 33 52 75 5a 58 52 77 5a 58 4a 73 63 79 31 6a 62 32 30 3d } //1 aHR0cDpkb3RuZXRwZXJscy1jb20=
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}