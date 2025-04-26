
rule Trojan_Win32_Danabot_ND_MTB{
	meta:
		description = "Trojan:Win32/Danabot.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {75 05 33 c0 89 46 0c 80 7e ?? ?? 75 1d e8 20 d5 ff ff 8b d8 85 db 74 12 8b c3 e8 5b e4 ff ff } //5
		$a_01_1 = {49 42 58 2e 49 42 53 74 6f 64 65 64 50 72 6f 63 } //1 IBX.IBStodedProc
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}