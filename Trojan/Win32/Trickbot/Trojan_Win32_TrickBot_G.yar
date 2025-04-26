
rule Trojan_Win32_TrickBot_G{
	meta:
		description = "Trojan:Win32/TrickBot.G,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {57 8b 45 04 05 ?? ?? ?? ?? 8b f0 6a ?? 5b 53 51 8b c6 8b 00 46 8b 0f 33 c1 59 88 07 47 4b 75 06 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}