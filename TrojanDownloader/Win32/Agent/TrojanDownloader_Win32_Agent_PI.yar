
rule TrojanDownloader_Win32_Agent_PI{
	meta:
		description = "TrojanDownloader:Win32/Agent.PI,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {68 74 74 70 3a 2f 2f 76 69 64 71 75 69 63 6b 2e 69 6e 66 6f 2f 63 67 69 2f [0-08] 2e 65 78 65 } //1
		$a_00_1 = {45 72 72 6f 72 21 20 43 61 6e 27 74 20 69 6e 69 74 69 61 6c 69 7a 65 20 70 6c 75 67 2d 69 6e 73 20 64 69 72 65 63 74 6f 72 79 2e 20 50 6c 65 61 73 65 20 74 72 79 20 61 67 61 69 6e 20 6c 61 74 65 72 2e } //1 Error! Can't initialize plug-ins directory. Please try again later.
		$a_00_2 = {5c 69 6e 65 74 63 2e 64 6c 6c } //1 \inetc.dll
		$a_00_3 = {5c 45 78 65 63 50 72 69 2e 64 6c 6c } //1 \ExecPri.dll
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}