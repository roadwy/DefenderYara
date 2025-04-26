
rule Trojan_BAT_Taskun_ASER_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ASER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 17 58 13 ?? 07 11 ?? 07 8e 69 5d 91 13 ?? 09 06 1f 16 5d 91 13 ?? 07 06 07 06 91 11 ?? 61 11 ?? 59 20 00 01 00 00 58 d2 9c 06 17 58 0a 06 07 8e 69 fe 04 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}