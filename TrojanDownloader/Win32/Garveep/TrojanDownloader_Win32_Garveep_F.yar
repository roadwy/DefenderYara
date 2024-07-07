
rule TrojanDownloader_Win32_Garveep_F{
	meta:
		description = "TrojanDownloader:Win32/Garveep.F,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {f3 ab 66 ab 90 02 10 ff 15 90 02 01 20 40 00 80 3e 25 0f 85 bb 00 00 00 90 00 } //1
		$a_00_1 = {41 6e 74 69 53 70 79 57 61 72 65 32 47 75 61 72 64 2e 65 78 65 } //1 AntiSpyWare2Guard.exe
		$a_00_2 = {52 30 33 41 43 37 46 30 } //1 R03AC7F0
		$a_00_3 = {56 33 4c 53 76 63 2e 65 78 65 } //1 V3LSvc.exe
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}