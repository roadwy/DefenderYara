
rule TrojanDownloader_O97M_Arkei_ASG_MSR{
	meta:
		description = "TrojanDownloader:O97M/Arkei.ASG!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {43 3a 5c 5c 55 73 65 72 73 5c 5c 50 75 62 6c 69 63 5c 5c 73 65 72 76 69 63 65 68 6f 6d 65 77 6f 72 6b 2e 65 5e 78 65 } //1 C:\\Users\\Public\\servicehomework.e^xe
		$a_00_1 = {63 75 67 64 77 70 6e 79 6b 67 68 78 2e 72 75 2f 62 71 39 37 39 67 35 64 66 77 62 6e 33 31 71 39 31 74 71 2e 62 6e 33 31 71 39 31 74 5e 78 62 6e 33 31 71 39 31 74 20 2d 6f } //1 cugdwpnykghx.ru/bq979g5dfwbn31q91tq.bn31q91t^xbn31q91t -o
		$a_00_2 = {2f 70 20 63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 20 2f 6d 20 6e 6f 74 65 70 61 64 2e 65 78 65 20 2f 63 } //1 /p c:\windows\system32 /m notepad.exe /c
		$a_00_3 = {62 65 6c 6c 61 2e 6c 6e 6b } //1 bella.lnk
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}