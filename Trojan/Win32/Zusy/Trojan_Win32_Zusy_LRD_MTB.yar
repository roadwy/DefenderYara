
rule Trojan_Win32_Zusy_LRD_MTB{
	meta:
		description = "Trojan:Win32/Zusy.LRD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 04 0a c6 b8 01 00 00 00 6b c8 07 8b 55 08 c6 04 0a c5 b8 01 00 00 00 c1 e0 03 8b 4d 08 c6 04 01 cd ba 01 00 00 00 6b c2 09 8b 4d 08 c6 04 01 00 c7 45 fc 00 00 00 00 } //30
	condition:
		((#a_01_0  & 1)*30) >=30
 
}