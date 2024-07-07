
rule Trojan_Win32_Tinba_GC_MTB{
	meta:
		description = "Trojan:Win32/Tinba.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f af d1 88 95 90 01 04 c7 85 90 01 08 0f be 85 90 01 04 69 c0 90 01 04 88 85 90 01 04 c7 85 90 01 08 8b 8d 90 01 04 81 e9 90 01 04 2b 8d 90 01 04 8b 95 90 01 04 2b d1 89 95 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}