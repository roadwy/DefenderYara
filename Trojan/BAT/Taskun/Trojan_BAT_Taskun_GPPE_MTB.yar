
rule Trojan_BAT_Taskun_GPPE_MTB{
	meta:
		description = "Trojan:BAT/Taskun.GPPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f 00 28 d0 00 00 0a 1f 10 62 0f 00 28 d1 00 00 0a 1e 62 60 0f 00 28 d2 00 00 0a 60 0b } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}