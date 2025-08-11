
rule Trojan_BAT_Taskun_EANM_MTB{
	meta:
		description = "Trojan:BAT/Taskun.EANM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 11 04 07 11 04 94 03 5a 1f 64 5d 9e 11 04 17 58 13 04 11 04 07 8e 69 32 e6 } //5
		$a_01_1 = {07 09 07 09 94 02 5a 1f 64 5d 9e 09 17 58 0d 09 07 8e 69 32 eb } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}