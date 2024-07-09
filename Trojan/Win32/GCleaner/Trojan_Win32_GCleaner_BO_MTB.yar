
rule Trojan_Win32_GCleaner_BO_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 0c 53 56 57 8b 45 14 50 e8 4e 54 04 00 e9 } //5
		$a_01_1 = {ec 83 ec 0c 53 56 57 8b 45 14 50 e8 02 54 04 00 e9 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=5
 
}
rule Trojan_Win32_GCleaner_BO_MTB_2{
	meta:
		description = "Trojan:Win32/GCleaner.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 56 8b 75 14 57 56 e8 [0-04] 6a 19 6a 14 6a 0b 6a 0a 68 [0-04] ff 15 [0-04] e9 } //5
		$a_01_1 = {0c 53 56 57 8b 45 14 50 e8 d2 53 04 00 e9 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=5
 
}