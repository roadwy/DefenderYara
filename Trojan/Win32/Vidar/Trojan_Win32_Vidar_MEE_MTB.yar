
rule Trojan_Win32_Vidar_MEE_MTB{
	meta:
		description = "Trojan:Win32/Vidar.MEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b c2 8b f8 8b 85 7c ec ff ff 8d 0c 06 33 d2 8b c6 f7 f7 8b 45 0c 8a 14 02 8b 85 78 ec ff ff 32 14 08 88 11 8d 8d 80 ec ff ff 51 e8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}