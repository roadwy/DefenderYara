
rule Trojan_Win32_Zenpak_RDH_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e0 8b 4d e4 31 d2 81 c1 c7 20 00 00 89 0d } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}