
rule Trojan_Win32_Androm_RA_MTB{
	meta:
		description = "Trojan:Win32/Androm.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6b c8 00 0f be 54 0d f4 b8 01 00 00 00 c1 e0 00 0f be 4c 05 f4 c1 f9 04 8d 14 91 8b 45 ec 03 45 f8 88 10 8b 4d f8 83 c1 01 89 4d f8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}