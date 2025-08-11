
rule Trojan_BAT_XWorm_AOAB_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AOAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 00 11 02 02 11 02 91 11 03 11 02 11 03 28 ?? 00 00 06 5d 6f ?? 00 00 0a 61 d2 9c 20 } //5
		$a_01_1 = {11 02 17 58 13 02 20 } //2
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}