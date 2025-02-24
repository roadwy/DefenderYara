
rule Trojan_Win32_Gozi_EAPL_MTB{
	meta:
		description = "Trojan:Win32/Gozi.EAPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 e8 05 03 44 24 30 33 d0 c7 05 d8 91 4f 00 00 00 00 00 8b 44 24 18 03 c7 33 d0 a1 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}