
rule TrojanDownloader_Win32_Busky_A{
	meta:
		description = "TrojanDownloader:Win32/Busky.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {42 00 43 00 75 73 65 72 33 32 2e 64 6c 6c } //1 BC獵牥㈳搮汬
		$a_00_1 = {42 00 43 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c } //1 BC敫湲汥㈳搮汬
		$a_00_2 = {43 00 6f 00 6d 00 53 00 70 00 65 00 63 00 } //1 ComSpec
		$a_00_3 = {47 65 74 45 6e 76 69 72 6f 6e 6d 65 6e 74 56 61 72 69 61 62 6c 65 41 } //1 GetEnvironmentVariableA
		$a_02_4 = {81 ec 84 00 00 00 68 ?? ?? 40 00 68 ?? ?? 40 00 c3 } //1
		$a_02_5 = {3b 4d 10 0f [0-08] 8b 55 08 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1+(#a_02_5  & 1)*1) >=6
 
}