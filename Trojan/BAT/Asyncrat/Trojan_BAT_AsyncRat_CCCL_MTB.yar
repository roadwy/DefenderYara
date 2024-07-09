
rule Trojan_BAT_AsyncRat_CCCL_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.CCCL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 08 06 08 91 20 ?? ?? ?? ?? 59 d2 9c 00 08 17 58 0c 08 06 8e 69 fe 04 0d 09 2d e3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}