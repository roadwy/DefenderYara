
rule Trojan_Win32_IcedId_SIBJ12_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ12!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {69 6e 63 6c 75 64 65 62 6c 75 65 5c 63 68 61 72 74 2e 70 64 62 } //1 includeblue\chart.pdb
		$a_03_1 = {83 c6 04 2c 90 02 0a 81 fe 90 01 04 90 02 0a 90 18 90 02 70 8b 2d 90 01 04 90 02 20 8b bc 2e 90 01 04 90 02 30 81 c7 90 01 04 90 02 10 89 bc 2e 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_IcedId_SIBJ12_MTB_2{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ12!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {4c 6f 75 64 6d 69 6e 65 2e 70 64 62 } //1 Loudmine.pdb
		$a_03_1 = {03 cd 89 4c 24 90 01 01 8b 29 90 02 30 8b 4c 24 90 1b 00 81 c5 90 01 04 90 02 10 89 29 90 02 30 8b 6c 24 90 01 01 90 02 10 83 c5 04 90 02 10 89 6c 24 90 1b 06 90 02 10 81 fd 90 01 04 0f 82 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_IcedId_SIBJ12_MTB_3{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ12!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {67 00 75 00 6e 00 63 00 6f 00 72 00 72 00 65 00 63 00 74 00 2e 00 65 00 78 00 65 00 } //1 guncorrect.exe
		$a_03_1 = {4d 85 ff 74 90 01 01 b8 90 01 04 90 02 0a 8b 15 90 01 04 8b 8c 02 90 01 04 81 c1 90 01 04 90 02 0a 89 8c 02 90 1b 04 83 c0 04 3d 90 01 04 72 90 01 01 90 02 20 4f 90 02 10 73 90 01 01 90 02 0a 83 ff 90 01 01 77 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}