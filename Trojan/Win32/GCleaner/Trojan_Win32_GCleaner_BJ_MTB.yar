
rule Trojan_Win32_GCleaner_BJ_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.BJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 56 ff 15 1c e5 46 00 8b 75 14 6a 00 6a 00 56 ff 15 ac e4 46 00 56 ff 15 b0 e4 46 00 e9 } //5
		$a_01_1 = {55 8b ec 56 ff 15 f8 e4 46 00 8b 75 14 6a 00 6a 00 56 ff 15 90 e4 46 00 56 ff 15 94 e4 46 00 e9 } //5
		$a_01_2 = {55 8b ec 56 8b 75 14 56 ff 15 00 b0 46 00 56 e8 e2 26 04 00 e9 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=5
 
}