
rule Virus_Win32_Expiro_RPY_MTB{
	meta:
		description = "Virus:Win32/Expiro.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {51 01 ca 53 54 50 53 52 ff d7 5b 59 50 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}