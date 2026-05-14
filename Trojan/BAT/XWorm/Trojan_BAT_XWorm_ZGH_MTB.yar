
rule Trojan_BAT_XWorm_ZGH_MTB{
	meta:
		description = "Trojan:BAT/XWorm.ZGH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {63 11 04 1e 11 05 59 1f 1f 5f 62 60 d2 13 04 07 08 11 04 09 20 ff 00 00 00 5d 61 d2 9c 08 17 58 0c 08 02 8e 69 32 c0 07 2a } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}