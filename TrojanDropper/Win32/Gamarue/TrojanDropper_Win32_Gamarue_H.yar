
rule TrojanDropper_Win32_Gamarue_H{
	meta:
		description = "TrojanDropper:Win32/Gamarue.H,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 31 89 45 ?? 8b 45 ?? 33 d2 f7 f7 66 8b 04 55 ?? ?? ?? ?? 66 89 04 71 85 f6 75 } //1
		$a_03_1 = {8a 0c 30 80 e9 ?? 32 ca ff 44 24 ?? 88 0c 30 39 7c 24 ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}