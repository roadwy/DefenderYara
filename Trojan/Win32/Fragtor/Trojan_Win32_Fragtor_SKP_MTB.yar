
rule Trojan_Win32_Fragtor_SKP_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.SKP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 c0 39 c3 74 09 8a 0c 02 88 0c 06 40 eb } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}