
rule Trojan_BAT_Taskun_ZBS_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ZBS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {26 02 11 21 11 29 6f ?? 00 00 0a 13 2b 11 0a 12 2b 28 ?? 00 00 0a 58 13 0a 11 0b 12 2b 28 ?? 00 00 0a 58 13 0b 11 0c 12 2b 28 ?? 00 00 0a 58 13 0c } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}