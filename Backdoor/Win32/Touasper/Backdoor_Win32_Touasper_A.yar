
rule Backdoor_Win32_Touasper_A{
	meta:
		description = "Backdoor:Win32/Touasper.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {f1 03 00 00 7c dd 46 39 7d fc 72 34 } //3
		$a_01_1 = {56 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 43 61 63 68 65 46 69 6c 65 41 } //1 VRLDownloadToCacheFileA
		$a_01_2 = {21 62 3d 7a 26 37 3f 63 63 2c 4d 51 3e } //1 !b=z&7?cc,MQ>
		$a_00_3 = {73 00 75 00 70 00 65 00 72 00 68 00 61 00 72 00 64 00 20 00 63 00 6f 00 72 00 70 00 2e 00 } //1 superhard corp.
		$a_01_4 = {44 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 DreateRemoteThread
		$a_01_5 = {43 6f 6d 70 75 74 65 72 20 6e 61 6d 65 3a 20 20 25 73 } //1 Computer name:  %s
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}