
rule Trojan_Win32_GCleaner_AGC_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.AGC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 8b 4e 10 f7 f3 8a 9a ac 9c 43 00 8b 56 14 88 5d f0 3b ca } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_GCleaner_AGC_MTB_2{
	meta:
		description = "Trojan:Win32/GCleaner.AGC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 01 0f 43 45 bc 6a 00 6a 03 ff 73 40 ff 73 3c 6a 50 50 56 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}