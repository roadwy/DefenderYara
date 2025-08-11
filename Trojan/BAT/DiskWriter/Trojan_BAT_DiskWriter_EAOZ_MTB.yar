
rule Trojan_BAT_DiskWriter_EAOZ_MTB{
	meta:
		description = "Trojan:BAT/DiskWriter.EAOZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b 15 06 07 02 07 ?? ?? ?? ?? ?? 20 00 01 00 00 5d d2 9c 07 17 58 0b 07 20 f8 2f 14 00 32 e3 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}