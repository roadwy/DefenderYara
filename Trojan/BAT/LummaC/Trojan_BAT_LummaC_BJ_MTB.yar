
rule Trojan_BAT_LummaC_BJ_MTB{
	meta:
		description = "Trojan:BAT/LummaC.BJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {14 0b 00 28 ?? 00 00 06 0b dd ?? 00 00 00 26 de f1 07 39 ?? 00 00 00 73 ?? 00 00 0a 0c 08 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 08 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 08 6f ?? 00 00 0a 07 16 07 8e 69 6f ?? 00 00 0a 0b dd ?? 00 00 00 08 39 ?? 00 00 00 08 6f ?? 00 00 0a dc 28 ?? 00 00 0a 07 6f ?? 00 00 0a 0d 09 14 28 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}