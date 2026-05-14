
rule Trojan_Win32_GCleaner_PGGD_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.PGGD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d0 01 d7 eb [0-0f] 33 [0-1f] 33 [0-0f] 8a a5 08 00 [0-0f] 03 [0-0a] 03 [0-0a] 03 [0-af] 2b [0-5f] 31 ?? 83 c6 04 83 c3 04 3b 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}