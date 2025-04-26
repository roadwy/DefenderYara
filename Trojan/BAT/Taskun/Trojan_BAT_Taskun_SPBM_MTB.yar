
rule Trojan_BAT_Taskun_SPBM_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SPBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {17 58 09 5d 13 0d 08 11 0b 91 11 0c 61 13 0e 08 11 0d 91 13 0f } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}