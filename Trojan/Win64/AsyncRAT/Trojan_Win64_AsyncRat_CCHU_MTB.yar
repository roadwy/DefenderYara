
rule Trojan_Win64_AsyncRat_CCHU_MTB{
	meta:
		description = "Trojan:Win64/AsyncRat.CCHU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 8d 8c 24 60 02 00 00 4c 8d 84 24 30 02 00 00 48 8d 15 ?? ?? 01 00 48 8d 0d ?? ?? 01 00 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}