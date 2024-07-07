
rule Trojan_Win32_Amadey_BAI_MTB{
	meta:
		description = "Trojan:Win32/Amadey.BAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {21 d1 09 c8 88 c1 8b 45 e4 88 08 8b 0d 90 02 04 a1 90 02 04 89 ca 81 ea 90 02 04 83 ea 01 81 c2 90 02 04 0f af ca 83 e1 01 83 f9 00 0f 94 c3 83 f8 0a 0f 9c c6 88 d8 34 ff 88 f4 80 f4 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}