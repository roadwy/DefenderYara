
rule Trojan_Win64_AsyncRat_CCJX_MTB{
	meta:
		description = "Trojan:Win64/AsyncRat.CCJX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 48 8b c7 49 f7 f6 49 8d 0c 39 41 0f b6 04 0a 42 32 04 02 88 01 48 ff c7 49 3b fd 72 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}