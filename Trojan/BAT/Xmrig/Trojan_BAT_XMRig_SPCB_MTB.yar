
rule Trojan_BAT_XMRig_SPCB_MTB{
	meta:
		description = "Trojan:BAT/XMRig.SPCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {05 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 08 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05 2b 1e 2b 20 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}