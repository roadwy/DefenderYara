
rule Trojan_Win32_Stealer_NE_MTB{
	meta:
		description = "Trojan:Win32/Stealer.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 45 f8 b8 d6 38 00 00 01 45 f8 8b 4d f8 8b 45 08 8a 0c 01 8b 15 90 01 04 5f 5e 88 0c 02 5b c9 c2 04 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}