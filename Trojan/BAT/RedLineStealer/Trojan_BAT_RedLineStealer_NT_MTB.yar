
rule Trojan_BAT_RedLineStealer_NT_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {57 9f a2 2b 09 0f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 da 00 00 00 4d 00 00 00 c3 01 00 00 df 01 00 00 aa 01 00 00 13 00 00 00 95 01 00 00 07 00 00 00 b8 00 00 00 08 00 00 00 8d 00 00 00 03 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}