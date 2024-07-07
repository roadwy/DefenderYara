
rule Trojan_Win32_Zusy_HNA_MTB{
	meta:
		description = "Trojan:Win32/Zusy.HNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 6a 02 6a 00 6a 00 6a 03 ff 35 90 01 04 e8 90 01 04 a3 90 01 04 6a 00 6a 00 6a 03 6a 00 6a 00 6a 01 ff 35 90 01 04 e8 90 01 04 a3 90 01 04 6a 00 50 e8 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}