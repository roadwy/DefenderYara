
rule TrojanSpy_Win32_Stildat_A{
	meta:
		description = "TrojanSpy:Win32/Stildat.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {7c 23 7c 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 7c 23 7c 43 6f 6d 6d 61 6e 64 } //1 |#|DownloadFile|#|Command
		$a_01_1 = {4d 3a 53 46 3f 63 6f 6d 6d 61 6e 64 49 64 3d 43 6d 64 52 65 73 75 6c 74 3d } //1 M:SF?commandId=CmdResult=
		$a_01_2 = {45 78 65 63 75 74 65 4b 4c } //1 ExecuteKL
		$a_01_3 = {47 65 74 43 6f 6e 66 69 67 3a 3a 3a } //1 GetConfig:::
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}