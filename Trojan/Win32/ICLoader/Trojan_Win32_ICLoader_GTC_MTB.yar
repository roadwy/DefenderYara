
rule Trojan_Win32_ICLoader_GTC_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.GTC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 6a ff 68 ?? e5 89 00 68 ?? 7d 89 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec ?? 53 56 57 89 65 ?? ff 15 } //10
		$a_03_1 = {55 8b ec 6a ff 68 ?? e6 89 00 68 ?? 7d 89 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}