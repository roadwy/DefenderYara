
rule Trojan_BAT_Taskun_EAHA_MTB{
	meta:
		description = "Trojan:BAT/Taskun.EAHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 08 1f 0a 5a 6f 32 00 00 0a 26 04 07 08 91 6f 33 00 00 0a 08 17 58 0c 08 03 32 e4 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}