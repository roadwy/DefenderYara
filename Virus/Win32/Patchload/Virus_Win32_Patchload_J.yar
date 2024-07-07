
rule Virus_Win32_Patchload_J{
	meta:
		description = "Virus:Win32/Patchload.J,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff d3 85 c0 0f 85 90 01 04 8b 45 f8 8b 50 08 8b 7c 02 08 3b fa 0f 87 90 01 04 81 ff 38 01 00 00 0f 82 90 01 04 68 90 01 04 e8 90 01 04 8b 75 ec 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}