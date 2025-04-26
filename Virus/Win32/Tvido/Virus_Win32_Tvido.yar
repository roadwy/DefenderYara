
rule Virus_Win32_Tvido{
	meta:
		description = "Virus:Win32/Tvido,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 45 f4 80 38 4d 0f 85 ?? 04 00 00 80 78 01 5a 0f 85 ?? 04 00 00 81 78 22 57 65 65 44 0f 84 ?? 04 00 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}