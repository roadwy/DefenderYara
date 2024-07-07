
rule Virus_Win32_Sality_AN{
	meta:
		description = "Virus:Win32/Sality.AN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 ff 00 00 00 8b 8d 90 01 02 ff ff 81 e1 ff 00 00 00 0f af c1 05 97 08 00 00 66 a3 90 01 04 8b 15 90 01 04 52 68 00 54 01 00 6a 00 6a 04 6a 00 6a ff ff 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}