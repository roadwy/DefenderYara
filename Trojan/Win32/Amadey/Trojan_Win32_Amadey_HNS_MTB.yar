
rule Trojan_Win32_Amadey_HNS_MTB{
	meta:
		description = "Trojan:Win32/Amadey.HNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 05 00 00 "
		
	strings :
		$a_03_0 = {e9 00 20 00 00 90 09 0a 00 eb 08 0f ?? ?? 00 00 00 00 00 } //20
		$a_01_1 = {31 cb 31 e1 83 ea 01 52 ff 0c 24 5a } //1
		$a_03_2 = {89 1c 24 e8 01 00 00 00 cc 8b 04 24 ?? 89 ?? 81 ?? 04 00 00 00 83 ?? 04 } //1
		$a_01_3 = {e1 6b 67 1a 45 12 3a 87 ac 17 5a 6b } //5
		$a_01_4 = {1c 6b 67 1a 45 12 3a 87 ac 17 5a 6b 72 bb 7d 00 } //5
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5) >=26
 
}