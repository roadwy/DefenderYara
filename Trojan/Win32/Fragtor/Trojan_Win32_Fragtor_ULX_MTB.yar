
rule Trojan_Win32_Fragtor_ULX_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.ULX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 4c 06 01 30 0c 06 40 3b c2 72 f4 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}