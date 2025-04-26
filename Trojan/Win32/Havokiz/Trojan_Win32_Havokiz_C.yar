
rule Trojan_Win32_Havokiz_C{
	meta:
		description = "Trojan:Win32/Havokiz.C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 81 ec f8 04 00 00 48 8d 7c 24 78 44 89 8c 24 58 05 00 00 48 8b ac 24 60 05 00 00 4c 8d 6c 24 78 f3 ab b9 59 00 00 00 48 c7 44 24 70 00 00 00 00 c7 44 24 78 68 00 00 00 c7 84 24 b4 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}