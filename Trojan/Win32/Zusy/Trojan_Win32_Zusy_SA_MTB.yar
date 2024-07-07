
rule Trojan_Win32_Zusy_SA_MTB{
	meta:
		description = "Trojan:Win32/Zusy.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 c6 8d 5b 90 01 01 33 c7 69 f8 90 01 04 8b c7 c1 e8 90 01 01 33 f8 0f b7 03 8b f0 66 85 c0 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}