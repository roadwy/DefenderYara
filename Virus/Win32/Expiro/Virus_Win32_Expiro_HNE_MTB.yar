
rule Virus_Win32_Expiro_HNE_MTB{
	meta:
		description = "Virus:Win32/Expiro.HNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {53 50 01 d8 54 52 57 50 ff d6 58 5b 52 90 09 04 00 40 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}