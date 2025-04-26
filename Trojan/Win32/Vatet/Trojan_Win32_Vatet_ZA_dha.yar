
rule Trojan_Win32_Vatet_ZA_dha{
	meta:
		description = "Trojan:Win32/Vatet.ZA!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 00 00 00 10 ?? ff 15 ?? ?? ?? ?? 8b ?? 83 ?? ff [0-06] 6a 00 6a 00 6a 00 6a 04 6a 00 ?? ff 15 90 07 08 01 0f 10 ?? ?? 66 0f f8 ?? 66 0f ef ?? 66 0f f8 ?? 0f 11 ?? ?? 83 ?? 10 3b ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}