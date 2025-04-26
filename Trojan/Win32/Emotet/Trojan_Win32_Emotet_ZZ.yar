
rule Trojan_Win32_Emotet_ZZ{
	meta:
		description = "Trojan:Win32/Emotet.ZZ,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {8b c8 8b d6 d3 e2 8b c6 8b cd d3 e0 03 d0 0f be c3 03 d0 8b 44 ?? ?? 2b d6 47 8b f2 8a 1f 84 db 75 de } //10
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*10) >=11
 
}