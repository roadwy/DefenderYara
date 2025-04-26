
rule Trojan_Win32_Winnti_ZD_dha{
	meta:
		description = "Trojan:Win32/Winnti.ZD!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {80 34 08 09 40 3b 45 ?? 7c f6 } //1
		$a_03_1 = {5f 60 7b 7d c7 85 ?? ?? ?? ?? 7c 68 65 48 c7 85 ?? ?? ?? ?? 65 65 66 6a } //1
		$a_03_2 = {4a 7b 6c 68 c7 85 ?? ?? ?? ?? 7d 6c 59 7b c7 85 ?? ?? ?? ?? 66 6a 6c 7a 66 c7 85 ?? ?? ?? ?? 7a 48 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}