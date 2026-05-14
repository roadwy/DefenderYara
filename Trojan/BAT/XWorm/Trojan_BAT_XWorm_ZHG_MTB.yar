
rule Trojan_BAT_XWorm_ZHG_MTB{
	meta:
		description = "Trojan:BAT/XWorm.ZHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 08 02 08 91 03 08 07 5d 91 61 08 1d 5a 20 ff 00 00 00 5f 61 d2 9c 08 20 10 27 00 00 5d 2d 06 16 28 ?? 00 00 0a 08 17 58 0c 08 02 8e 69 32 d0 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}