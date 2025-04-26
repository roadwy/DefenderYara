
rule TrojanDropper_Win32_QQplug_A{
	meta:
		description = "TrojanDropper:Win32/QQplug.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {66 6e 55 6e 4c 6f 61 64 44 72 76 00 66 6e 4b 69 6c 6c 4b 49 53 00 00 00 66 6e 43 6c 69 63 6b 4c 6f 61 64 44 72 76 } //1
		$a_03_1 = {33 f6 50 68 ?? ?? 40 00 6a 69 56 e8 ?? ?? ff ff 83 c4 10 89 ?? f0 } //1
		$a_03_2 = {56 50 8d 45 fc 6a 02 50 ff 75 f8 c7 45 fc 50 45 00 00 ff d7 ff 75 f8 ff 15 ?? ?? 40 00 5f } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}