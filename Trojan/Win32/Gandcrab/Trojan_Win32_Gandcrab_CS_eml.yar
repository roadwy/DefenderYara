
rule Trojan_Win32_Gandcrab_CS_eml{
	meta:
		description = "Trojan:Win32/Gandcrab.CS!eml,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 6a 00 ff 15 [0-02] 60 40 00 a1 ?? f8 40 00 03 85 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 8d ?? ?? ?? ?? 8a 89 3d 34 03 00 88 08 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}