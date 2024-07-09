
rule Trojan_Win32_Paramis_E{
	meta:
		description = "Trojan:Win32/Paramis.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 55 08 03 55 ?? 0f be ?? 01 8b 4d ?? 0f be ?? ?? ?? ?? ?? 33 c2 8b 4d ?? 03 4d ?? 88 01 } //1
		$a_00_1 = {47 6f 6f 67 6c 65 20 54 6f 6f 6c 62 61 72 00 00 47 45 54 00 79 61 68 6f 6f 2e 63 6f 6d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}