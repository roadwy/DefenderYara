
rule Trojan_Win32_Azorult_BAG_MTB{
	meta:
		description = "Trojan:Win32/Azorult.BAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {58 23 01 f8 83 d1 04 f7 d0 8d 40 da f8 83 d8 01 29 d8 89 c3 89 07 83 c7 04 f8 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}