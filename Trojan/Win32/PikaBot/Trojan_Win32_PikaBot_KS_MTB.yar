
rule Trojan_Win32_PikaBot_KS_MTB{
	meta:
		description = "Trojan:Win32/PikaBot.KS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {16 f6 f1 af 31 92 ?? ?? ?? ?? ?? b0 ?? 79 ?? 25 ?? ?? ?? ?? c4 b7 ?? ?? ?? ?? 46 e3 ?? ?? ?? ?? ?? e8 a8 ?? ?? ?? e9 } //1
		$a_03_1 = {9e 02 cf b5 ?? b3 ?? a9 ?? ?? ?? ?? ?? e8 b4 ?? ?? ?? e9 } //1
		$a_01_2 = {43 72 61 73 68 } //1 Crash
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}