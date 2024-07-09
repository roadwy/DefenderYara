
rule Trojan_BAT_Redline_IG_MTB{
	meta:
		description = "Trojan:BAT/Redline.IG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {0c 16 13 04 2b 21 00 07 11 04 08 11 04 08 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 07 11 04 91 61 d2 9c 00 11 04 17 58 13 04 11 04 07 8e 69 fe 04 13 05 11 05 2d d2 } //10
		$a_80_1 = {5b 4b 55 5d 5b 52 57 41 5d } //[KU][RWA]  1
		$a_01_2 = {49 6e 76 6f 6b 65 } //1 Invoke
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}