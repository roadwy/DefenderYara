
rule TrojanSpy_Win32_Banker_AII{
	meta:
		description = "TrojanSpy:Win32/Banker.AII,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {74 1e 8d 45 ?? 50 b9 01 00 00 00 8b d3 8b 45 ?? e8 ?? ?? ?? ?? 8b 55 ?? 8d 45 ?? e8 ?? ?? ?? ?? 43 4e 0f 85 } //3
		$a_00_1 = {53 65 23 6e 68 61 20 64 6f 20 63 61 23 72 74 } //1 Se#nha do ca#rt
		$a_01_2 = {6f 20 64 6f 20 70 6c 75 67 69 6e 20 70 61 72 61 20 72 65 61 6c 69 7a 61 72 20 65 73 74 65 20 70 72 6f 63 65 64 69 6d 65 6e 74 6f } //1 o do plugin para realizar este procedimento
		$a_00_3 = {49 6e 74 65 23 72 6e 23 65 74 23 20 40 42 2a 61 23 6e 40 6b 40 69 2a 6e 67 40 } //1 Inte#rn#et# @B*a#n@k@i*ng@
		$a_00_4 = {2a 2f 3a 2a 70 74 2a 74 23 68 } //1 */:*pt*t#h
	condition:
		((#a_03_0  & 1)*3+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}