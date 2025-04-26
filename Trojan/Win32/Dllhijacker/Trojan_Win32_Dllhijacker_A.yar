
rule Trojan_Win32_Dllhijacker_A{
	meta:
		description = "Trojan:Win32/Dllhijacker.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {7b 32 44 45 41 36 35 38 46 2d 35 34 43 31 2d 34 32 32 37 2d 41 46 39 42 2d 32 36 30 41 42 35 46 43 33 35 34 33 7d } //1 {2DEA658F-54C1-4227-AF9B-260AB5FC3543}
		$a_01_1 = {5c 43 4c 53 49 44 5c 7b 32 32 32 32 32 32 32 32 32 32 32 32 32 7d 5c 49 6e 70 72 6f 63 53 65 72 76 65 72 33 32 } //1 \CLSID\{2222222222222}\InprocServer32
		$a_01_2 = {5c 6d 73 74 72 61 63 65 72 2e 64 6c 6c } //1 \mstracer.dll
		$a_01_3 = {5c 53 54 55 44 49 4f 5c 31 30 35 39 2d 20 76 69 72 75 73 2e 77 69 6e 2e 74 72 6f 6a 61 6e } //1 \STUDIO\1059- virus.win.trojan
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}