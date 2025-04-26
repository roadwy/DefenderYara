
rule Trojan_Win32_GCleaner_BM_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 6a 00 e8 [0-04] 8b 45 14 50 ff 15 [0-04] e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}