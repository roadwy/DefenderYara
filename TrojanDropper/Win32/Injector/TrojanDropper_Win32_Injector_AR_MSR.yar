
rule TrojanDropper_Win32_Injector_AR_MSR{
	meta:
		description = "TrojanDropper:Win32/Injector.AR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 00 65 00 78 00 45 00 6e 00 63 00 2e 00 45 00 58 00 45 00 } //1 HexEnc.EXE
		$a_01_1 = {48 00 65 00 78 00 45 00 6e 00 63 00 20 00 4d 00 46 00 43 00 20 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 } //1 HexEnc MFC Application
		$a_01_2 = {4d 4f 66 48 3f 36 4d 34 32 46 32 35 32 6c 6f 4c 74 30 4e } //1 MOfH?6M42F252loLt0N
		$a_01_3 = {37 3f 43 4f 73 53 77 79 69 74 68 38 48 59 6e 6e 50 } //1 7?COsSwyith8HYnnP
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}