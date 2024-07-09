
rule Trojan_Win32_Paramis_C{
	meta:
		description = "Trojan:Win32/Paramis.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 03 ?? ?? ?? ff ff 0f be ?? 01 8b ?? ?? ?? ff ff 0f be ?? ?? ?? ?? ?? 33 c8 8b 95 ?? ?? ff ff 03 95 ?? ?? ff ff 88 0a } //1
		$a_00_1 = {47 6f 6f 67 6c 65 20 54 6f 6f 6c 62 61 72 00 00 47 45 54 00 79 61 68 6f 6f 2e 63 6f 6d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}