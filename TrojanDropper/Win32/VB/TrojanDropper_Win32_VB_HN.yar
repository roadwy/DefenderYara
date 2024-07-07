
rule TrojanDropper_Win32_VB_HN{
	meta:
		description = "TrojanDropper:Win32/VB.HN,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 00 74 00 65 00 6d 00 70 00 2e 00 2e 00 7a 00 69 00 70 00 } //2 \temp..zip
		$a_00_1 = {4e 00 6f 00 72 00 74 00 6f 00 6e 00 20 00 41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 20 00 41 00 75 00 74 00 6f 00 20 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 } //2 Norton Antivirus Auto Protect Service
		$a_01_2 = {42 69 6e 64 65 72 5f 53 65 72 76 65 72 } //3 Binder_Server
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_01_2  & 1)*3) >=7
 
}