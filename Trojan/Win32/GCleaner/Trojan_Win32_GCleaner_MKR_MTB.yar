
rule Trojan_Win32_GCleaner_MKR_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.MKR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 95 dc f7 ff ff 8b 85 d8 f7 ff ff 30 14 38 83 fb 0f 75 ?? 68 ?? ?? ?? ?? 6a 00 6a 00 6a 00 ff 15 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}