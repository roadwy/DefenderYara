
rule Trojan_Win32_Bamital_O{
	meta:
		description = "Trojan:Win32/Bamital.O,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 ff d0 c9 c2 04 00 b8 00 00 00 00 c9 c2 04 00 55 8b ec 83 7d 0c 01 75 (09|10) } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}