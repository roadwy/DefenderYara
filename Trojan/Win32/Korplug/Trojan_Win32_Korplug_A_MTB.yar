
rule Trojan_Win32_Korplug_A_MTB{
	meta:
		description = "Trojan:Win32/Korplug.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 ff 15 58 90 01 01 40 00 8b f0 b8 02 00 00 00 66 89 45 ec 0f b7 45 0c 50 ff 15 90 01 02 40 00 66 89 45 ee 8b 46 0c 6a 10 8b 00 8b 00 89 45 f0 8d 45 ec 50 ff 77 08 ff 15 70 90 01 01 40 00 83 f8 ff 75 90 01 01 ff 77 0c ff d3 68 e8 03 00 00 ff 77 0c ff 15 08 90 01 01 40 00 8b 75 e8 eb 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}