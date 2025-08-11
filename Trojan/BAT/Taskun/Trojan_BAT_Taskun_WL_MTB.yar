
rule Trojan_BAT_Taskun_WL_MTB{
	meta:
		description = "Trojan:BAT/Taskun.WL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {69 17 59 91 1f 70 61 0b 02 8e 69 17 58 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}