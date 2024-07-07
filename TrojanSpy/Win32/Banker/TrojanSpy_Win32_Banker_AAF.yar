
rule TrojanSpy_Win32_Banker_AAF{
	meta:
		description = "TrojanSpy:Win32/Banker.AAF,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {66 03 f0 66 69 c6 cd b1 66 05 ff cf 8b f0 80 c3 02 } //2
		$a_03_1 = {70 72 61 71 75 65 6d 3d 90 02 20 40 90 03 0b 09 68 6f 74 6d 61 69 6c 2e 63 6f 6d 67 6d 61 69 6c 2e 63 6f 6d 90 00 } //2
		$a_00_2 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 61 64 64 20 61 6c 6c 6f 77 65 64 70 72 6f 67 72 61 6d } //1 netsh firewall add allowedprogram
		$a_00_3 = {32 65 33 63 33 36 35 31 2d 62 31 39 63 2d 34 64 64 39 2d 61 39 37 39 2d 39 30 31 65 63 33 65 39 33 30 61 66 } //1 2e3c3651-b19c-4dd9-a979-901ec3e930af
		$a_01_4 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 63 6f 6e 74 72 6f 6c 65 5f 64 65 70 5f 63 6f 6d 75 6e 69 63 61 63 61 6f 20 57 48 45 52 45 20 4e 5f 4d 43 41 44 44 52 45 53 53 20 3d 27 } //1 SELECT * FROM controle_dep_comunicacao WHERE N_MCADDRESS ='
	condition:
		((#a_00_0  & 1)*2+(#a_03_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}