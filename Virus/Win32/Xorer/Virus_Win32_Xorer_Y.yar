
rule Virus_Win32_Xorer_Y{
	meta:
		description = "Virus:Win32/Xorer.Y,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 8d 80 fe ff ff 51 8d 4d d8 e8 90 01 02 00 00 6a 00 68 90 01 02 40 00 6a 00 6a 00 ff 15 90 01 02 40 00 68 90 01 02 40 00 8d 4d d8 89 45 c4 e8 90 01 02 00 00 83 f8 ff 0f 84 34 02 00 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}