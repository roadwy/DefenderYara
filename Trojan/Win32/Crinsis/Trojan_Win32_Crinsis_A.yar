
rule Trojan_Win32_Crinsis_A{
	meta:
		description = "Trojan:Win32/Crinsis.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {c7 45 e8 00 00 00 00 c7 85 ?? ?? ff ff 00 00 00 00 c7 85 ?? ?? ff ff 7a fc ff 7f 0f be 05 ?? ?? 00 10 0f be 0d ?? ?? 00 10 } //1
		$a_03_1 = {86 03 00 00 0f bf 0d ?? ?? 00 10 0f bf 15 ?? ?? 00 10 2b ca 89 [0-06] 0f be 05 ?? ?? 00 10 8b 0d ?? ?? 00 10 03 c8 89 } //1
		$a_03_2 = {b9 e1 00 00 00 33 c0 8d bd ?? ?? ff ff f3 ab aa } //1
		$a_03_3 = {99 f7 f9 0f bf 15 ?? 81 00 10 88 84 15 ?? ?? ff ff } //1
		$a_03_4 = {b9 06 00 00 00 33 c0 8d bd ?? ?? ff ff f3 ab c6 85 ?? ?? ff ff 00 b9 06 00 00 00 33 c0 8d bd ?? ?? ff ff f3 ab b9 4b 00 00 00 33 c0 8d bd ?? ?? ff ff f3 ab 0f } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}