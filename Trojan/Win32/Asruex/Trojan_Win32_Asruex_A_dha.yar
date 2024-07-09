
rule Trojan_Win32_Asruex_A_dha{
	meta:
		description = "Trojan:Win32/Asruex.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 1c 8d 4c 24 30 56 8a 1c 30 80 c3 ?? e8 ?? ?? ?? ?? 46 8b 00 88 1c 28 3b f7 72 e2 } //1
		$a_01_1 = {85 c0 74 06 c6 46 6c 20 eb 04 c6 46 6c 24 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}