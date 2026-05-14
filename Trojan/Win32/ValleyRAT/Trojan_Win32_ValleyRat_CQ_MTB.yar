
rule Trojan_Win32_ValleyRat_CQ_MTB{
	meta:
		description = "Trojan:Win32/ValleyRat.CQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {34 56 8b 8d 88 fe ff ff 83 c4 04 88 04 11 42 89 95 94 fe ff ff eb 06 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}