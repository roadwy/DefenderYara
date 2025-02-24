
rule Trojan_Win32_Fragtor_JT_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.JT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {60 e8 00 00 00 00 5d 81 ed 10 00 00 00 81 ed c4 a2 9c 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}