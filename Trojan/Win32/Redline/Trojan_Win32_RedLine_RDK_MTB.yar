
rule Trojan_Win32_RedLine_RDK_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c8 33 d2 8b c6 f7 f1 8a 82 ?? ?? ?? ?? 32 c3 88 04 2e 46 3b f7 } //2
		$a_01_1 = {76 00 62 00 63 00 2e 00 65 00 78 00 65 00 } //1 vbc.exe
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}