
rule TrojanDropper_Win32_Agent_AS{
	meta:
		description = "TrojanDropper:Win32/Agent.AS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {58 40 ff e0 ff 15 ?? ?? ?? ?? c3 55 89 e5 83 ?? ?? e8 ea ff ff ff } //1
		$a_02_1 = {c7 00 54 45 4d 50 c6 40 04 00 51 8d 85 ?? ?? ?? ?? 68 00 01 00 00 50 50 ff 15 } //1
		$a_00_2 = {8b 55 08 8b 75 10 01 d6 8a 16 30 ca ff 45 10 88 16 8b 4d 10 3b 4d 0c 72 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}