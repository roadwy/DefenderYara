
rule Trojan_Win32_Oyster_OYT_MTB{
	meta:
		description = "Trojan:Win32/Oyster.OYT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 02 8d 52 ff 8a 0c 3e 0f b6 80 ?? ?? ?? ?? 88 04 3e 47 0f b6 c1 0f b6 80 } //2
		$a_01_1 = {8d 4b 0c 6a 00 0f 47 4b 0c 6a 00 6a 03 6a 00 6a 00 68 bb 01 00 00 51 57 ff 15 } //2
		$a_01_2 = {4e 5a 54 5c 50 72 6f 6a 65 63 74 44 5f 57 69 6e 49 6e 65 74 5c 43 6c 65 61 6e 55 70 5c 52 65 6c 65 61 73 65 5c 43 6c 65 61 6e 55 70 2e 70 64 62 } //1 NZT\ProjectD_WinInet\CleanUp\Release\CleanUp.pdb
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}