
rule Trojan_Win32_GCleaner_MON_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.MON!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c0 01 1e ba 8a a5 08 00 03 55 c8 03 d3 03 c2 ba 39 19 00 00 03 d0 81 ea 39 19 00 00 31 16 83 c3 04 83 c6 04 3b 5d cc 72 d6 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}