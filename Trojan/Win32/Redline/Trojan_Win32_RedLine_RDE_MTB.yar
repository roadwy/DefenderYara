
rule Trojan_Win32_RedLine_RDE_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {b9 01 00 00 00 c1 e1 00 0f be 54 0d c4 c1 e2 04 88 55 c2 0f be 45 c3 0f be 4d c2 03 c1 8b 55 98 03 55 c8 88 02 8b 45 c8 83 c0 01 } //2
		$a_01_1 = {49 00 72 00 65 00 61 00 20 00 49 00 6e 00 6e 00 6f 00 } //1 Irea Inno
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}