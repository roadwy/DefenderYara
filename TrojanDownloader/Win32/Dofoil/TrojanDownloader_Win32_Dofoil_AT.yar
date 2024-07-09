
rule TrojanDownloader_Win32_Dofoil_AT{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.AT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 fa f7 13 00 00 75 ?? 6a 00 } //1
		$a_03_1 = {b1 6d b0 6c 68 68 91 47 00 88 [0-05] c6 ?? ?? ?? ?? ?? 73 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}