
rule Trojan_BAT_Taskun_EM_MTB{
	meta:
		description = "Trojan:BAT/Taskun.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 11 07 91 06 75 03 00 00 1b 11 05 91 13 08 07 61 11 08 61 13 09 11 0d 20 c0 01 00 00 94 20 88 1a 00 00 59 13 0b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}