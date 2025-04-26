
rule Trojan_BAT_Remcos_NEJ_MTB{
	meta:
		description = "Trojan:BAT/Remcos.NEJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 9a 2b 0f 2b 14 2b 19 2a 02 2b ed 6f ?? 00 00 0a 2b ed 28 ?? 00 00 2b 2b ea 6f ?? 00 00 0a 2b e5 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}