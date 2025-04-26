
rule TrojanSpy_Win32_Kolnops_A{
	meta:
		description = "TrojanSpy:Win32/Kolnops.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2d 75 73 65 72 20 64 75 6d 70 73 40 7a 65 72 6f 6b 6f 6f 6c 2e 63 63 } //2 -user dumps@zerokool.cc
		$a_01_1 = {52 61 70 6f 72 74 20 64 65 20 6c 61 20 25 63 6f 6d 70 75 74 65 72 6e 61 6d 65 25 } //1 Raport de la %computername%
		$a_01_2 = {2d 73 6d 74 70 20 33 37 2e 35 39 2e 32 36 2e 39 34 } //1 -smtp 37.59.26.94
		$a_01_3 = {2d 70 61 73 73 20 31 32 33 34 71 77 65 72 } //1 -pass 1234qwer
		$a_01_4 = {2d 61 74 74 61 63 68 20 62 61 63 6b 75 70 2e 37 7a } //1 -attach backup.7z
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}