
rule Virus_Win32_Sirefef_R{
	meta:
		description = "Virus:Win32/Sirefef.R,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e8 46 fe ff ff 85 c0 7c 11 8b 45 fc 66 39 70 06 74 08 56 56 56 83 c0 0c ff d0 68 00 80 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Virus_Win32_Sirefef_R_2{
	meta:
		description = "Virus:Win32/Sirefef.R,SIGNATURE_TYPE_ARHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e8 46 fe ff ff 85 c0 7c 11 8b 45 fc 66 39 70 06 74 08 56 56 56 83 c0 0c ff d0 68 00 80 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}