
rule Trojan_Win32_Vidar_IND_MTB{
	meta:
		description = "Trojan:Win32/Vidar.IND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 89 4e 34 c1 e9 18 33 c8 c1 e8 08 81 e1 ff 00 00 00 33 04 8d c0 ca 44 00 81 e2 fd ff 00 00 89 46 38 8b 4e 3c 83 ca 02 8b c2 83 f0 01 0f af c2 c1 e8 08 32 45 08 43 88 44 0b ff 3b 5d 0c 72 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}