
rule Trojan_BAT_Taskun_AFBB_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AFBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 11 11 10 61 20 ff 00 00 00 5f 13 14 09 ?? ?? 00 00 01 11 11 11 10 11 12 20 ff 00 00 00 5f 11 13 20 ff 00 00 00 5f 11 14 } //5
		$a_03_1 = {11 10 1f 13 5a 11 11 1f 17 5a 58 11 04 ?? ?? 00 00 01 20 00 01 00 00 20 } //2
		$a_03_2 = {11 11 1f 11 5a 11 10 1f 1f 5a 58 11 04 ?? ?? 00 00 01 20 00 01 00 00 20 } //2
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=9
 
}