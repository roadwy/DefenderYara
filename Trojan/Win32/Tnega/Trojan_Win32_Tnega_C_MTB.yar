
rule Trojan_Win32_Tnega_C_MTB{
	meta:
		description = "Trojan:Win32/Tnega.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f0 8b 4d f4 01 c1 8b 45 f0 8b 55 08 01 c2 8b 45 f0 89 4d ec 8b 4d f8 89 55 e8 99 f7 f9 8b 45 fc 01 d0 8b 4d e8 0f be 09 0f be 10 31 d1 8b 45 ec 88 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}