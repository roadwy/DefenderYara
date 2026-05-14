
rule Trojan_BAT_Taskun_ZHG_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ZHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 15 13 21 11 21 17 91 13 26 11 15 8e 69 13 23 11 23 1f 0b 58 1d 11 26 58 61 d2 13 1f 11 21 16 91 11 21 18 91 1e 62 60 11 1f 19 62 58 13 1c 16 13 17 16 13 0a 2b 56 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}