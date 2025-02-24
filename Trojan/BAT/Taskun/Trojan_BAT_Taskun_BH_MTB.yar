
rule Trojan_BAT_Taskun_BH_MTB{
	meta:
		description = "Trojan:BAT/Taskun.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {17 13 15 09 11 13 07 11 13 91 11 04 11 14 95 61 d2 9c 00 11 13 17 58 13 13 11 13 07 8e 69 fe 04 } //3
		$a_01_1 = {11 04 11 05 95 11 04 11 06 95 58 20 ff 00 00 00 5f } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}