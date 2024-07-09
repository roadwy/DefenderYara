
rule TrojanDownloader_Win32_Pedrp_A{
	meta:
		description = "TrojanDownloader:Win32/Pedrp.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {64 6f 77 6e 20 66 69 6c 65 20 73 75 63 63 65 73 73 } //1 down file success
		$a_03_1 = {3c 0d 74 04 3c 0a 75 08 c6 84 14 ?? 00 00 00 00 80 bc 14 90 1b 00 00 00 00 2f 74 03 4a 79 dc } //1
		$a_03_2 = {ff d0 85 c0 74 0a c7 05 ?? ?? ?? ?? 00 00 00 00 56 8b 35 ?? ?? ?? ?? 57 68 ?? ?? ?? ?? 8b 0e 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 56 ff 51 54 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}