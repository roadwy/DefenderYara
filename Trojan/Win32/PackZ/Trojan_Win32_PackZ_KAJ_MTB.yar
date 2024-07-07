
rule Trojan_Win32_PackZ_KAJ_MTB{
	meta:
		description = "Trojan:Win32/PackZ.KAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 1e 21 d2 21 c2 89 c2 81 e3 90 01 04 29 d1 81 ea 90 01 04 49 31 1f b8 90 01 04 21 c9 47 09 d0 89 d0 46 f7 d2 29 d0 21 d2 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}