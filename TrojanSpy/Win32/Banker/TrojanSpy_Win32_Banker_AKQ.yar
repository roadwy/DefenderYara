
rule TrojanSpy_Win32_Banker_AKQ{
	meta:
		description = "TrojanSpy:Win32/Banker.AKQ,SIGNATURE_TYPE_PEHSTR_EXT,09 00 08 00 0a 00 00 "
		
	strings :
		$a_01_0 = {c1 e0 06 03 45 e8 89 45 e4 83 45 ec 06 83 7d ec 08 7c 49 83 6d ec 08 8b 4d ec 8b 45 e4 d3 e8 89 45 e8 8b 4d ec bb 01 00 00 00 d3 e3 } //2
		$a_01_1 = {c1 e0 06 03 d8 89 5d f0 83 c7 06 83 ff 08 7c 42 83 ef 08 8b cf 8b 5d f0 d3 eb 8b cf b8 01 00 00 00 d3 e0 8b c8 8b 45 f0 } //2
		$a_01_2 = {28 00 49 00 44 00 5f 00 50 00 43 00 2c 00 20 00 45 00 52 00 52 00 4f 00 52 00 29 00 20 00 56 00 61 00 6c 00 75 00 65 00 73 00 20 00 20 00 28 00 3a 00 49 00 44 00 5f 00 50 00 43 00 2c 00 20 00 3a 00 45 00 52 00 52 00 4f 00 52 00 29 00 } //1 (ID_PC, ERROR) Values  (:ID_PC, :ERROR)
		$a_01_3 = {3a 00 55 00 53 00 42 00 4c 00 4f 00 47 00 2c 00 20 00 44 00 41 00 54 00 41 00 5f 00 43 00 4f 00 50 00 49 00 41 00 20 00 3d 00 20 00 47 00 45 00 54 00 44 00 41 00 54 00 45 00 28 00 29 00 } //1 :USBLOG, DATA_COPIA = GETDATE()
		$a_01_4 = {7b 00 32 00 45 00 33 00 43 00 33 00 36 00 35 00 31 00 2d 00 42 00 31 00 39 00 43 00 2d 00 34 00 44 00 44 00 39 00 2d 00 41 00 39 00 37 00 39 00 2d 00 39 00 30 00 31 00 45 00 43 00 33 00 45 00 39 00 33 00 30 00 41 00 46 00 7d 00 } //1 {2E3C3651-B19C-4DD9-A979-901EC3E930AF}
		$a_01_5 = {2e 00 47 00 62 00 49 00 65 00 68 00 4f 00 62 00 6a 00 00 00 } //1
		$a_01_6 = {2e 00 47 00 62 00 50 00 6c 00 75 00 67 00 69 00 6e 00 4f 00 62 00 6a 00 00 00 } //1
		$a_01_7 = {43 00 68 00 72 00 6f 00 6d 00 65 00 5f 00 57 00 69 00 64 00 67 00 65 00 74 00 57 00 69 00 6e 00 5f 00 } //1 Chrome_WidgetWin_
		$a_01_8 = {4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 55 00 49 00 57 00 69 00 6e 00 64 00 6f 00 77 00 43 00 6c 00 61 00 73 00 73 00 00 00 } //1
		$a_03_9 = {49 00 54 00 41 00 20 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 42 00 42 00 20 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 43 00 45 00 46 00 20 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 53 00 54 00 41 00 20 00 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_03_9  & 1)*2) >=8
 
}