
rule Trojan_BAT_Taskun_KAH_MTB{
	meta:
		description = "Trojan:BAT/Taskun.KAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 01 11 0d 91 11 02 11 05 1f 16 5d 91 61 13 09 } //5
		$a_03_1 = {11 09 11 01 11 05 17 58 11 04 5d 91 59 20 00 ?? 00 00 58 20 00 ?? 00 00 5d 13 0a } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}