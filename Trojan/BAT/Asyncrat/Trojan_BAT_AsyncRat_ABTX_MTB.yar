
rule Trojan_BAT_AsyncRat_ABTX_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.ABTX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 00 08 20 00 04 00 00 58 28 ?? 00 00 2b 07 02 08 20 00 04 00 00 20 7c 01 00 00 20 78 01 00 00 28 ?? 00 00 06 0d 1b 13 0d 38 ?? ?? ?? ff 1b 13 06 1f 0a 13 0d } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}