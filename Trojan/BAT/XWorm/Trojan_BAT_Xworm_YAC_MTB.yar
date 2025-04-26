
rule Trojan_BAT_Xworm_YAC_MTB{
	meta:
		description = "Trojan:BAT/Xworm.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 59 08 1f 0a 5d 59 20 00 01 00 00 58 20 00 01 00 00 5d d1 13 04 07 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}