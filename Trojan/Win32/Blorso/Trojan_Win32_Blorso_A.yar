
rule Trojan_Win32_Blorso_A{
	meta:
		description = "Trojan:Win32/Blorso.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d8 80 eb 01 72 0c 74 28 fe cb 74 42 fe cb 74 5c eb 76 8d 45 f8 50 e8 ?? ?? ?? ?? 8b 45 fc 83 c0 04 50 8b 45 f8 83 c0 04 50 e8 } //1
		$a_03_1 = {76 70 6a 00 56 68 01 04 00 00 8d 85 ?? ?? ff ff 50 8b 45 fc 50 e8 ?? ?? ?? ?? 85 c0 74 54 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}