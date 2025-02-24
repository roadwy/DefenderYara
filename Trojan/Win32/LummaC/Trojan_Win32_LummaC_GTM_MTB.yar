
rule Trojan_Win32_LummaC_GTM_MTB{
	meta:
		description = "Trojan:Win32/LummaC.GTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {40 00 00 e0 2e 72 73 72 63 20 20 20 00 10 00 00 00 30 05 00 00 00 00 00 00 70 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 } //5
		$a_01_1 = {40 00 00 e0 2e 74 61 67 67 61 6e 74 00 30 00 00 00 60 2f } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}
rule Trojan_Win32_LummaC_GTM_MTB_2{
	meta:
		description = "Trojan:Win32/LummaC.GTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {40 00 00 e0 2e 72 73 72 63 00 00 00 ?? ?? 00 00 00 30 05 00 00 ?? 00 00 00 70 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 } //5
		$a_03_1 = {40 00 00 c0 20 20 20 20 20 20 20 20 00 ?? ?? 00 00 50 05 00 00 02 00 00 00 } //5
		$a_01_2 = {25 75 73 65 72 61 70 70 64 61 74 61 25 5c 52 65 73 74 61 72 74 41 70 70 2e 65 78 65 } //1 %userappdata%\RestartApp.exe
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*1) >=11
 
}