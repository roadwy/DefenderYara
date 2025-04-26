
rule Trojan_BAT_StealerC_CXII_MTB{
	meta:
		description = "Trojan:BAT/StealerC.CXII!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 16 0d 38 1d 00 00 00 00 08 07 09 07 8e 69 5d 91 02 09 91 61 28 ?? ?? ?? ?? 6f ?? ?? ?? ?? 00 00 09 17 58 0d 09 02 8e 69 fe 04 13 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}