
rule Trojan_Win32_Ghoul_AQ_MTB{
	meta:
		description = "Trojan:Win32/Ghoul.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 05 9c f9 12 02 58 5d 06 02 c7 05 a0 f9 12 02 5c 5d 06 02 c7 05 a4 f9 12 02 60 5d 06 02 c7 05 ac f9 12 02 64 5d 06 02 c7 05 a8 f9 12 02 68 5d 06 02 c7 05 b4 f9 12 02 64 5d 06 02 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}