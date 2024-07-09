
rule TrojanSpy_Win32_Banker_HN{
	meta:
		description = "TrojanSpy:Win32/Banker.HN,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {b9 0b 00 00 00 6a 00 6a 00 49 75 f9 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 } //2
		$a_01_1 = {5c 64 6f 77 6e 6c 6f 61 64 65 64 20 70 72 6f 67 72 61 6d 20 66 69 6c 65 73 5c 2a 2e 2a 00 } //1
		$a_01_2 = {44 35 32 32 39 37 30 30 36 30 44 43 35 43 44 45 35 34 44 36 31 35 36 41 46 32 34 38 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}