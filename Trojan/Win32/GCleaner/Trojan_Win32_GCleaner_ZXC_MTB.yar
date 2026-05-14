
rule Trojan_Win32_GCleaner_ZXC_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.ZXC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d0 03 55 9c 52 6a 00 e8 ?? ?? ?? ?? 5a 2b d0 52 6a 00 e8 ?? ?? ?? ?? 5a 03 d0 31 13 83 c6 04 83 c3 04 3b 75 d0 0f 82 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}