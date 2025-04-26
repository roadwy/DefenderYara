
rule Trojan_Win32_Farfli_B_MTB{
	meta:
		description = "Trojan:Win32/Farfli.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {9c 60 e8 00 00 00 00 5d b8 07 00 00 00 2b e8 8d b5 19 fe ff ff 8b 06 83 f8 00 74 11 8d b5 41 fe ff ff 8b 06 83 f8 01 0f 84 4b 02 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}