
rule Trojan_Win32_Zusy_RA_MTB{
	meta:
		description = "Trojan:Win32/Zusy.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 83 e0 03 0f b6 80 90 01 04 30 81 90 01 04 8d 82 90 01 04 03 c1 83 e0 03 0f b6 80 90 01 04 30 81 90 01 04 8d 86 90 01 04 03 c1 83 e0 03 0f b6 80 90 01 04 30 81 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}