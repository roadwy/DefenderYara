
rule Trojan_Win32_Azorult_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 45 f0 8b 45 f0 89 45 ec 8b 4d f4 8b c3 d3 e8 03 45 d0 89 45 f8 8b 45 ec 31 45 fc 8b 45 fc 33 45 f8 29 45 e4 89 45 fc 8d 45 e8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}