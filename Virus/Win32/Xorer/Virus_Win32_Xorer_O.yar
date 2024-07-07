
rule Virus_Win32_Xorer_O{
	meta:
		description = "Virus:Win32/Xorer.O,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 7c 24 10 ee be 09 00 75 08 6a 00 ff 15 90 01 02 40 00 33 c0 c2 10 00 68 90 01 02 40 00 68 90 01 02 40 00 ff 15 90 01 02 40 00 85 c0 75 0c 50 68 90 01 02 40 00 ff 15 90 01 02 40 00 33 c0 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}