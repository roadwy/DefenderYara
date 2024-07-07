
rule Trojan_Win32_Farfli_Y_MTB{
	meta:
		description = "Trojan:Win32/Farfli.Y!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 30 58 02 10 56 e8 90 01 02 00 00 83 c4 08 85 c0 0f 85 90 01 02 00 00 68 44 58 02 10 56 e8 90 01 02 00 00 83 c4 08 85 c0 0f 85 90 01 02 00 00 68 60 58 02 10 56 e8 90 01 02 00 00 83 c4 08 85 c0 0f 85 90 01 02 00 00 68 70 58 02 10 56 e8 90 01 02 00 00 83 c4 08 85 c0 0f 85 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}