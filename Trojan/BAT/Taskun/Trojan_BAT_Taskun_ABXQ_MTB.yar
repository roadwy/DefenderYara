
rule Trojan_BAT_Taskun_ABXQ_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ABXQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 0d 2b 2f 11 0d 09 5d 13 0e 11 0d 09 5b 13 0f 08 11 0e 11 0f 6f ?? 00 00 0a 13 10 07 11 05 12 10 28 ?? 00 00 0a 9c 11 05 17 58 13 05 11 0d 17 58 13 0d 11 0d 09 11 04 5a 32 c9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}