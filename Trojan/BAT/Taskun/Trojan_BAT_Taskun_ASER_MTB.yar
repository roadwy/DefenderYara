
rule Trojan_BAT_Taskun_ASER_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ASER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 17 58 13 90 01 01 07 11 90 01 01 07 8e 69 5d 91 13 90 01 01 09 06 1f 16 5d 91 13 90 01 01 07 06 07 06 91 11 90 01 01 61 11 90 01 01 59 20 00 01 00 00 58 d2 9c 06 17 58 0a 06 07 8e 69 fe 04 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}