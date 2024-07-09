
rule Trojan_BAT_Taskun_GAO_MTB{
	meta:
		description = "Trojan:BAT/Taskun.GAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 16 0d 2b 1d 07 09 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 13 05 08 11 05 6f ?? 00 00 0a 09 18 58 0d 09 07 6f ?? 00 00 0a fe 04 13 06 11 06 2d d4 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}