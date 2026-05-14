
rule Trojan_Win32_GCleaner_ZZS_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.ZZS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 d6 03 d0 b9 b2 84 31 00 03 ca 81 e9 b2 84 31 00 2b c8 31 0b 83 c6 04 83 c3 04 3b 75 d4 72 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}