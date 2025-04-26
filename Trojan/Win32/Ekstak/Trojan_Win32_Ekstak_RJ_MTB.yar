
rule Trojan_Win32_Ekstak_RJ_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 08 56 68 0d ef 64 00 e8 cf 6d fb ff e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RJ_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 6a 00 e8 ?? 3b 04 00 8b 45 14 50 e8 ?? 3b 04 00 e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RJ_MTB_3{
	meta:
		description = "Trojan:Win32/Ekstak.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6c 4c 00 ff 15 ?? f3 4b 00 6a 4e ff 15 ?? f5 4b 00 6a 00 ff 15 ?? f3 4b 00 8b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}