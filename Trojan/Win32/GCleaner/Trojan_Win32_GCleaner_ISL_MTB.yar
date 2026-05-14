
rule Trojan_Win32_GCleaner_ISL_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.ISL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 fa 03 fe 03 f8 6a 00 e8 2e c1 f8 ff 50 8b c7 5a 2b c2 31 03 83 c6 04 83 c3 04 3b 75 cc 72 d4 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}