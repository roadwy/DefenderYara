
rule Trojan_Win32_Fragtor_KAF_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.KAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 0a 4e 81 c6 90 01 04 40 81 e1 90 01 04 09 f6 4b 81 c6 90 01 04 31 0f f7 d0 b8 90 01 04 81 c7 90 01 04 01 c3 01 f6 81 c2 90 01 04 89 c3 4e 21 f0 81 ff 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}