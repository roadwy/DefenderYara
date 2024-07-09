
rule Trojan_Win32_Loader_ZY{
	meta:
		description = "Trojan:Win32/Loader.ZY,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 45 fc 50 68 40 00 00 00 68 ?? 0a 00 00 68 ?? ?? ?? ?? 68 ff ff ff ff ff 15 } //1
		$a_03_1 = {0a 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? b8 ?? ?? ?? ?? ff d0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}