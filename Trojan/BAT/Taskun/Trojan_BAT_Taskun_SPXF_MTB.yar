
rule Trojan_BAT_Taskun_SPXF_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SPXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 1b 11 18 11 09 91 13 22 11 18 11 09 11 22 11 23 61 11 1d 19 58 61 11 2c 61 d2 9c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}