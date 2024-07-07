
rule Trojan_Win32_Copak_KAQ_MTB{
	meta:
		description = "Trojan:Win32/Copak.KAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {47 21 f8 31 11 29 c0 01 ff 81 ef 90 01 04 81 c1 90 01 04 09 ff 39 d9 75 d0 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}