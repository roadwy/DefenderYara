
rule Trojan_Win32_Lokibot_SF_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.SF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 c4 10 5f 5e c3 90 05 10 01 90 80 f2 cd 88 10 90 05 10 01 90 c3 90 00 } //1
		$a_02_1 = {bb 01 00 00 00 90 05 10 01 90 8b c8 03 cb 73 90 01 01 e8 90 01 04 90 05 10 01 90 c6 01 90 01 01 90 05 10 01 90 43 81 fb 90 01 04 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Lokibot_SF_MTB_2{
	meta:
		description = "Trojan:Win32/Lokibot.SF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec eb 90 01 01 90 05 05 01 90 8a 45 08 90 05 05 01 90 30 01 90 05 05 01 90 eb 90 01 01 90 05 05 01 90 90 05 05 01 90 8b 4d 0c eb 90 01 01 5d c2 90 00 } //1
		$a_03_1 = {8b 06 03 c3 50 68 90 01 01 00 00 00 ff 15 90 01 04 ff 06 81 3e 90 01 04 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}