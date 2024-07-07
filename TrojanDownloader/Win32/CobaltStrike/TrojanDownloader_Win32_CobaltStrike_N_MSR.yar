
rule TrojanDownloader_Win32_CobaltStrike_N_MSR{
	meta:
		description = "TrojanDownloader:Win32/CobaltStrike.N!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {65 6e 68 61 6e 63 65 64 2d 67 6f 6f 67 6c 65 2e 63 6f 6d } //enhanced-google.com  1
		$a_81_1 = {43 6f 6e 74 72 6f 6c 5f 52 75 6e 44 4c 4c 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 41 78 6c 6e 73 74 53 56 5c 78 6c 73 72 64 2e 63 70 6c } //1 Control_RunDLL "C:\ProgramData\AxlnstSV\xlsrd.cpl
	condition:
		((#a_80_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}