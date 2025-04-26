
rule Trojan_BAT_XMRig_SWA_MTB{
	meta:
		description = "Trojan:BAT/XMRig.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 6f 0e 00 00 0a 0b 06 6f ?? 00 00 0a 07 28 ?? 00 00 0a 0c 08 6f ?? 00 00 0a 7e 02 00 00 04 25 3a 17 00 00 00 26 7e 01 00 00 04 fe 06 06 00 00 06 73 16 00 00 0a 25 80 02 00 00 04 28 ?? 00 00 2b 0d 09 14 28 ?? 00 00 0a 39 4b 00 00 00 09 72 8d 00 00 70 1f 1c 6f ?? 00 00 0a 13 0d 11 0d 14 28 ?? 00 00 0a 39 2f 00 00 00 14 13 0e 11 0d 6f ?? 00 00 0a 3a 08 00 00 00 09 28 ?? 00 00 0a 13 0e 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}