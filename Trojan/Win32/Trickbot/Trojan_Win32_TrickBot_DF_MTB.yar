
rule Trojan_Win32_TrickBot_DF_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 08 40 84 c9 75 ?? 2b c2 8b f8 33 c9 33 d2 8b c1 f7 f7 41 8a 92 ?? ?? ?? ?? 30 54 31 ff 81 f9 ?? ?? ?? ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}