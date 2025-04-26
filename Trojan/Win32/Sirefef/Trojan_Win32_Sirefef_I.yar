
rule Trojan_Win32_Sirefef_I{
	meta:
		description = "Trojan:Win32/Sirefef.I,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 40 10 8b 70 48 8b (1d|3d) ?? ?? ?? ?? 33 (|) db ff } //1
		$a_03_1 = {8b 75 0c 83 c4 0c 8d 85 ?? ?? ?? ?? 50 ff 75 ?? c7 85 90 1b 00 01 00 01 00 89 75 0c ff 15 ?? ?? ?? ?? 85 c0 7c ?? 6a 40 68 00 10 00 00 8d 45 0c 50 } //1
		$a_03_2 = {83 c4 0c 6a 40 68 00 10 00 00 8d 45 fc 50 57 8d 85 ?? ?? ff ff 50 ff 75 08 c7 85 ?? ?? ff ff 02 00 01 00 89 75 fc ff 15 ?? ?? ?? ?? 85 c0 7c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}
rule Trojan_Win32_Sirefef_I_2{
	meta:
		description = "Trojan:Win32/Sirefef.I,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 40 10 8b 70 48 8b (1d|3d) ?? ?? ?? ?? 33 (|) db ff } //1
		$a_03_1 = {8b 75 0c 83 c4 0c 8d 85 ?? ?? ?? ?? 50 ff 75 ?? c7 85 90 1b 00 01 00 01 00 89 75 0c ff 15 ?? ?? ?? ?? 85 c0 7c ?? 6a 40 68 00 10 00 00 8d 45 0c 50 } //1
		$a_03_2 = {83 c4 0c 6a 40 68 00 10 00 00 8d 45 fc 50 57 8d 85 ?? ?? ff ff 50 ff 75 08 c7 85 ?? ?? ff ff 02 00 01 00 89 75 fc ff 15 ?? ?? ?? ?? 85 c0 7c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}