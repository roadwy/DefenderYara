
rule Trojan_BAT_NanoCore_MIB_MTB{
	meta:
		description = "Trojan:BAT/NanoCore.MIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {16 9a 13 04 73 90 01 09 11 04 90 09 2f 00 0b 28 90 01 04 06 07 28 90 01 13 0c 08 72 90 01 09 0d 09 6f 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}