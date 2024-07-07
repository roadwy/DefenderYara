
rule TrojanDownloader_Win32_Nythug_B{
	meta:
		description = "TrojanDownloader:Win32/Nythug.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4e 75 6c 6c 73 6f 66 74 20 49 6e 73 74 61 6c 6c 20 53 79 73 74 65 6d } //1 Nullsoft Install System
		$a_01_1 = {5c 45 78 65 63 50 72 69 2e 64 6c 6c } //1 \ExecPri.dll
		$a_01_2 = {6d 76 4e 61 74 2e 65 78 65 } //1 mvNat.exe
		$a_00_3 = {5c 53 4d 53 63 76 68 6f 73 74 2e 65 78 65 00 68 74 74 70 3a 2f 2f 70 6c 65 78 63 6f 2e 63 6f 2e 63 63 2f 73 74 6c 63 32 2f 69 63 6d 6e 74 72 2e 65 78 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}