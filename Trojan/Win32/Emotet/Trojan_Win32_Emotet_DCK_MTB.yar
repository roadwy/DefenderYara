
rule Trojan_Win32_Emotet_DCK_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DCK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 00 50 e8 ?? ?? ?? ?? 33 d2 8b c5 b9 ?? ?? ?? ?? f7 f1 8b 44 24 ?? 8a 0c 02 8b 44 24 ?? 30 0c 28 8b 44 24 } //2
		$a_02_1 = {6a 00 6a 00 ff 15 ?? ?? ?? ?? 33 d2 8b c6 b9 ?? ?? ?? ?? f7 f1 8a 04 3e 8a 14 2a 32 c2 88 04 3e [0-03] 3b f3 75 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=2
 
}