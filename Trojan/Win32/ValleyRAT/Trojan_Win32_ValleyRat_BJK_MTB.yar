
rule Trojan_Win32_ValleyRat_BJK_MTB{
	meta:
		description = "Trojan:Win32/ValleyRat.BJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff d5 99 b9 3e 00 00 00 f7 f9 46 3b f3 8a 54 14 10 88 54 3e ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}