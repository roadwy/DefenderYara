
rule TrojanDropper_Win32_Rbot_A{
	meta:
		description = "TrojanDropper:Win32/Rbot.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 04 01 00 00 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 68 00 10 40 00 68 ?? ?? ?? ?? ff 15 } //1
		$a_02_1 = {72 42 6f 74 4c 6f 63 61 6c 2e 65 78 65 00 4d 5a 90 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}