
rule Trojan_BAT_Taskun_BQ_MTB{
	meta:
		description = "Trojan:BAT/Taskun.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 17 58 8c ?? 00 00 01 6f ?? ?? 00 0a 00 38 ?? 00 00 00 11 0a 16 30 05 38 ?? 00 00 00 19 8d ?? 00 00 01 25 16 12 09 28 ?? ?? 00 0a 9c 25 17 12 09 28 ?? ?? 00 0a 9c 25 18 12 09 28 ?? ?? 00 0a 9c 13 0d 11 0a 8d ?? 00 00 01 13 0e 16 13 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}