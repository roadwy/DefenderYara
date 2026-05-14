
rule Trojan_Win32_GCleaner_NNS_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.NNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 45 d0 03 c6 03 c7 89 45 bc c7 45 ac b2 84 31 00 6a 00 e8 ?? ?? ?? ?? 8b 55 bc 03 55 ac 81 ea b2 84 31 00 2b d7 03 c2 31 03 83 c6 04 83 c3 04 3b 75 d4 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}