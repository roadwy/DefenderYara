
rule TrojanSpy_Win32_Gauss_plugin_A{
	meta:
		description = "TrojanSpy:Win32/Gauss.plugin!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {c7 45 fc 09 00 00 00 ff 75 f0 83 4d fc ff 8b cf e8 ?? ?? ?? ?? 81 c3 04 18 00 00 53 83 ec 1c b8 ?? ?? ?? ?? 8b f4 89 65 ec e8 ?? ?? ?? ?? c7 45 fc 0a 00 00 00 } //1
		$a_02_1 = {6a 02 57 6a 05 68 00 00 00 40 50 ff 15 ?? ?? ?? ?? 8b f0 83 fe ff 75 ?? ff 15 ?? ?? ?? ?? 8b d8 83 4d fc ff } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}