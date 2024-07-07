
rule Trojan_Win32_Wiszr_B{
	meta:
		description = "Trojan:Win32/Wiszr.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 64 6c 6c 00 72 75 6e 6d 65 00 73 74 6f 70 00 } //1 搮汬爀湵敭猀潴p
		$a_01_1 = {00 69 73 77 69 7a 61 72 64 2e 37 7a 00 } //1
		$a_01_2 = {69 6e 64 65 78 65 72 2e 65 78 65 20 2d 70 6f 6f 6c 69 70 3d } //1 indexer.exe -poolip=
		$a_01_3 = {63 69 64 61 65 6d 6f 6e 2e 65 78 65 20 2d 63 20 70 72 6f 78 79 2e 63 6f 6e 66 } //1 cidaemon.exe -c proxy.conf
		$a_01_4 = {64 77 6d 2e 65 78 65 20 2d 70 6f 6f 6c 69 70 3d } //1 dwm.exe -poolip=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}