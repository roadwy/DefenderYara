
rule Virus_Win32_Konor_RS_MTB{
	meta:
		description = "Virus:Win32/Konor.RS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 04 39 33 c6 25 ff 00 00 00 c1 ee 08 33 b4 85 fc fb ff ff 41 3b ca 72 e6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}