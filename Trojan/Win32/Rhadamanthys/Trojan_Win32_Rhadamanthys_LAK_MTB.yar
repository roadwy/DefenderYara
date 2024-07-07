
rule Trojan_Win32_Rhadamanthys_LAK_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.LAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c3 c1 e8 05 03 45 f8 8b f3 c1 e6 04 03 75 f4 33 c6 8d 34 1a 33 c6 29 45 08 8b 45 08 8b 75 08 c1 e8 05 03 45 fc c1 e6 04 03 f7 33 c6 8b 75 08 03 f2 33 c6 2b d8 81 c2 47 86 c8 61 ff 4d 10 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}