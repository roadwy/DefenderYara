
rule Trojan_BAT_Taskun_SPMF_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SPMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 0d 91 11 0e 61 13 0f 11 0d 17 58 07 8e 69 5d 13 10 07 11 10 91 13 11 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}