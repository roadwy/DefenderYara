
rule Trojan_Win64_Emotet_BJ_MTB{
	meta:
		description = "Trojan:Win64/Emotet.BJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 31 d2 45 88 d3 48 8b 8d 90 01 04 8b 95 90 01 04 03 95 90 01 04 2b 95 90 01 04 4c 63 ca 46 88 1c 09 8b 85 90 01 04 83 c0 90 01 01 89 85 90 01 04 8b 85 90 01 04 83 c0 90 01 01 89 85 90 01 04 e9 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}