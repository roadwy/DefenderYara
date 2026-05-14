
rule Trojan_Win32_GCleaner_PGGH_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.PGGH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c0 01 1e ba 8a a5 08 00 03 55 c8 03 d3 03 d0 b9 39 19 00 00 03 ca 81 e9 39 19 00 00 2b c8 31 0e 83 c3 04 83 c6 04 3b 5d cc 72 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}