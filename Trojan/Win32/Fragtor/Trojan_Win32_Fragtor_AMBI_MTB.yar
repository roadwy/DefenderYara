
rule Trojan_Win32_Fragtor_AMBI_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.AMBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 da 09 fe 31 f2 88 14 08 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}