
rule Trojan_BAT_Redline_NEAU_MTB{
	meta:
		description = "Trojan:BAT/Redline.NEAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 06 03 11 06 91 07 11 06 07 8e 69 5d 91 61 08 61 d2 6f 90 01 01 00 00 0a 00 00 11 06 17 58 13 06 11 06 03 8e 69 fe 04 13 07 11 07 2d d4 90 00 } //10
		$a_01_1 = {52 50 46 3a 53 6d 61 72 74 41 73 73 65 6d 62 6c 79 } //1 RPF:SmartAssembly
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}