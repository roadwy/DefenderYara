
rule Trojan_Win32_GCleaner_WBM_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.WBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 00 e8 5c 8a fa ff 6a 00 e8 55 8a fa ff 6a 00 e8 4e 8a fa ff 6a 00 e8 47 8a fa ff 6a 00 e8 40 8a fa ff 6a 00 e8 39 8a fa ff 8b 45 b8 03 45 a8 2d 0d e0 00 00 2b c7 03 45 9c 31 03 83 c6 04 83 c3 04 3b 75 d0 72 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}