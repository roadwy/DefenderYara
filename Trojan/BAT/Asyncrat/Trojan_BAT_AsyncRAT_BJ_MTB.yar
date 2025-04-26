
rule Trojan_BAT_AsyncRAT_BJ_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.BJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 02 17 59 6f ?? 00 00 0a 06 7b ?? 00 00 04 8e 69 58 0c 07 02 6f ?? 00 00 0a 08 59 0d 06 7b } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}