
rule Trojan_Win32_GCleaner_CA_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 0c 53 56 57 68 34 19 47 00 68 04 01 00 00 ff 15 c0 f2 46 00 e9 } //5
		$a_03_1 = {55 8b ec 83 ec 0c 53 56 57 8b 45 14 50 e8 ?? 4d 04 00 e9 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=5
 
}