
rule Trojan_Win32_Vundo_RV{
	meta:
		description = "Trojan:Win32/Vundo.RV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 00 00 01 00 6a 00 8d 85 ?? ?? fe ff 50 e8 ?? ?? ?? ?? 83 c4 0c 8d 8d ?? ?? fe ff 51 8b 95 ?? ?? fe ff 52 8d 85 ?? ?? fe ff 50 8b 8d ?? ?? ff ff 51 ff 95 ?? ?? fe ff } //1
		$a_03_1 = {6a 02 8b 85 ?? ?? ff ff 50 ff 55 ?? 85 c0 75 12 ff 15 ?? ?? ?? ?? 83 f8 7a 74 07 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}