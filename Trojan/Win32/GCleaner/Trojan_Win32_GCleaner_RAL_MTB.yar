
rule Trojan_Win32_GCleaner_RAL_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.RAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 d0 52 6a 00 e8 02 4b fa ff 5a 2b d0 52 6a 00 e8 f7 4a fa ff 5a 03 d0 31 13 83 c6 04 83 c3 04 3b 75 d4 72 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}