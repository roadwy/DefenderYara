
rule TrojanSpy_Win32_Banker_AOK{
	meta:
		description = "TrojanSpy:Win32/Banker.AOK,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {83 e8 04 8b 00 89 ?? ?? 33 f6 bf 00 01 00 00 66 83 eb 43 74 ?? 66 ff cb 0f } //1
		$a_01_1 = {42 00 61 00 6e 00 6b 00 20 00 6f 00 66 00 20 00 41 00 6d 00 65 00 72 00 69 00 63 00 61 00 20 00 6c 00 6f 00 67 00 2d 00 69 00 6e 00 } //1 Bank of America log-in
		$a_01_2 = {43 00 68 00 72 00 6f 00 6d 00 65 00 5f 00 57 00 69 00 64 00 67 00 65 00 74 00 57 00 69 00 6e 00 5f 00 31 00 } //1 Chrome_WidgetWin_1
		$a_01_3 = {4d 00 4f 00 5a 00 49 00 4c 00 4c 00 41 00 55 00 49 00 57 00 49 00 4e 00 44 00 4f 00 57 00 43 00 4c 00 41 00 53 00 53 00 } //1 MOZILLAUIWINDOWCLASS
		$a_01_4 = {42 00 41 00 4e 00 43 00 4f 00 42 00 52 00 41 00 53 00 49 00 4c 00 43 00 4f 00 4d 00 42 00 52 00 } //1 BANCOBRASILCOMBR
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}