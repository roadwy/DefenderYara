
rule Trojan_Win32_Rimecud_ARMI_MTB{
	meta:
		description = "Trojan:Win32/Rimecud.ARMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 55 68 d7 4a 4a 00 64 ff 30 64 89 20 8b c3 8b 10 ff 52 ?? ba f0 4a 4a 00 8b c3 8b 08 ff 51 ?? 8d 45 f8 8b 4d fc ba 10 4b 4a 00 e8 ?? ?? ?? ?? 8b 55 f8 8b c3 8b 08 ff 51 ?? ba 28 4b 4a 00 8b c3 8b 08 ff 51 38 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}