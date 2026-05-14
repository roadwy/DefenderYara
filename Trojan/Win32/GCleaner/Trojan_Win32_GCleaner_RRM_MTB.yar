
rule Trojan_Win32_GCleaner_RRM_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.RRM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 b8 03 55 a8 81 ea 0d e0 00 00 2b d7 03 55 9c 2b d0 31 13 83 c6 04 83 c3 04 3b 75 d0 72 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}