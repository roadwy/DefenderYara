
rule Trojan_Win32_RedLine_RDBG_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 43 3c 8b 44 18 78 03 c3 89 45 dc 8b 70 20 8b 40 18 03 f3 89 45 e0 85 c0 74 31 8b 06 8d 4d e4 03 c3 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}