
rule Trojan_Win32_Zenpak_RJ_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ba 6d 78 29 cc 89 44 24 ?? 89 c8 f7 e2 c1 ea 08 69 c2 41 01 00 00 29 c1 89 c8 83 e8 02 89 4c 24 ?? 89 44 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}