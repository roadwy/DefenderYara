
rule Trojan_Win32_Jaik_TL_MTB{
	meta:
		description = "Trojan:Win32/Jaik.TL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 1e 65 00 be 4a 6a 24 b6 4a 6a 24 7e 4a 6a 24 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}