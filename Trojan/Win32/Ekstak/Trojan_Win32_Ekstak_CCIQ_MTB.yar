
rule Trojan_Win32_Ekstak_CCIQ_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.CCIQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 18 53 56 57 e8 ?? ?? de ff 89 45 fc e9 ?? ?? ?? ff 20 10 00 00 00 00 00 00 00 43 56 20 20 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_CCIQ_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.CCIQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 10 53 56 57 e8 ?? ?? f5 ff 89 45 fc e9 } //1
		$a_03_1 = {ff 15 a4 f4 4b 00 68 ?? 59 4c 00 a3 ?? 5b 4c 00 ff 15 10 f0 4b 00 6a 00 66 c7 05 ?? 5c 4c 00 7f 00 e8 cf 13 0a 00 01 05 ?? 5b 4c 00 ff 15 0c f0 4b 00 8b f0 81 e6 ff 00 00 00 83 fe 06 0f 93 c0 83 fe 06 a2 ?? 5c 4c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}