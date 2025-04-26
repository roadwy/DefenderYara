
rule Trojan_Win32_Glupteba_EAVF_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.EAVF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 8a 8c 30 01 24 0a 00 88 0c 32 8b e5 5d c3 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}