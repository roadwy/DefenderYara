
rule Trojan_BAT_Taskun_KAQ_MTB{
	meta:
		description = "Trojan:BAT/Taskun.KAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 09 91 11 0c 61 07 11 0d 91 59 13 0e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}