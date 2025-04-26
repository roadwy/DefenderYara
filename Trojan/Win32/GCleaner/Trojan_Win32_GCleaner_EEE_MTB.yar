
rule Trojan_Win32_GCleaner_EEE_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.EEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d b5 d4 f7 ff ff c7 85 d4 f7 ff ff 00 00 00 00 e8 ?? ?? ?? ?? 8a 95 d4 f7 ff ff 8b 85 dc f7 ff ff 8b b5 d8 f7 ff ff 30 14 30 83 7d 0c 0f 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}