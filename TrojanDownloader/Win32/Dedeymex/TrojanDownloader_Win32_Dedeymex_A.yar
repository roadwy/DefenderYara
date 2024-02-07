
rule TrojanDownloader_Win32_Dedeymex_A{
	meta:
		description = "TrojanDownloader:Win32/Dedeymex.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {78 78 63 63 76 2e 6d 79 73 78 63 2e 69 6e 66 6f 3a 37 37 37 2f 6c 6f 61 64 69 6e 67 2f 66 2e 74 78 74 3f 64 64 3d } //01 00  xxccv.mysxc.info:777/loading/f.txt?dd=
		$a_01_1 = {6e 73 52 61 6e 64 6f 6d 2e 64 6c 6c 00 47 65 74 52 61 6e 64 6f 6d } //01 00  獮慒摮浯搮汬䜀瑥慒摮浯
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 67 61 6e 6e 69 00 } //01 00 
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 6f 6b 71 71 00 } //00 00  体呆䅗䕒潜煫q
	condition:
		any of ($a_*)
 
}