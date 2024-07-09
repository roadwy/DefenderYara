
rule TrojanDropper_Win32_Rochap_gen_A{
	meta:
		description = "TrojanDropper:Win32/Rochap.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {24 0f 32 d8 80 f3 0a 8d 45 fc e8 ?? ?? ?? ?? 8b 55 fc 8a 54 3a ff 80 e2 f0 02 d3 88 54 38 ff 46 8b 45 f4 e8 ?? ?? ?? ?? 3b f0 7e 05 } //1
		$a_03_1 = {b8 60 ea 00 00 e8 ?? ?? ?? ?? eb 0c 53 } //1
		$a_03_2 = {6a 02 68 80 00 00 00 6a 00 8b 45 f8 e8 ?? ?? ?? ?? b9 02 00 00 00 ba 00 00 00 40 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}