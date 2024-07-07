
rule Trojan_BAT_NjRAT_KAZ_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.KAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 09 07 09 91 19 8d 90 01 01 00 00 01 25 d0 90 01 01 00 00 04 28 90 01 01 00 00 0a 09 19 5d 91 61 d2 9c 00 09 17 58 0d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}