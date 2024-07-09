
rule TrojanSpy_Win32_Ursnif_HB{
	meta:
		description = "TrojanSpy:Win32/Ursnif.HB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {61 74 74 72 69 62 20 2d 73 20 2d 72 20 2d 68 25 31 0d 0a 3a [0-10] 64 65 6c 20 25 31 } //1
		$a_03_1 = {00 43 4c 49 45 4e 54 36 34 90 05 08 01 00 43 4c 49 45 4e 54 33 32 00 } //1
		$a_03_2 = {ff 75 08 6a 00 68 00 04 00 00 ff 15 ?? ?? ?? ?? 8b f0 85 f6 74 ?? 8d 45 fc 50 56 ff d7 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}