
rule Trojan_Win32_Zenpak_AW_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 ec b9 ab aa aa aa 89 45 e4 f7 e1 c1 ea 03 6b c2 0c 8b 4d e4 29 c1 89 c8 83 e8 09 89 4d e0 89 45 dc 74 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}