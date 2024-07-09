
rule Virus_Win32_Ursnif_gen_B{
	meta:
		description = "Virus:Win32/Ursnif.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {00 53 59 53 49 4e 46 4f 00 } //1
		$a_01_1 = {00 53 43 52 45 45 4e 53 48 4f 54 00 } //1 匀剃䕅华佈T
		$a_01_2 = {2f 70 6b 69 2f 6d 73 63 6f 72 70 2f 63 72 6c 2f 4d 53 49 54 } //1 /pki/mscorp/crl/MSIT
		$a_01_3 = {63 00 6d 00 64 00 20 00 2f 00 43 00 20 00 22 00 64 00 72 00 69 00 76 00 65 00 72 00 71 00 75 00 65 00 72 00 79 00 2e 00 65 00 78 00 65 00 20 00 3e 00 3e 00 20 00 25 00 73 00 22 00 } //1 cmd /C "driverquery.exe >> %s"
		$a_01_4 = {2f 73 63 72 69 70 74 3f 75 3d } //1 /script?u=
		$a_03_5 = {8b c3 2b c6 a9 fe ff ff ff 74 3f 56 ff 15 ?? ?? ?? ?? 83 f8 02 74 05 83 f8 04 75 13 8d 45 f0 50 ff 75 ec ff 75 08 51 56 8b cf e8 ?? ?? ?? ?? 8b 45 fc 8d 73 02 8d 9d ec fd ff ff 2b c6 6a 00 03 c3 5b d1 f8 85 c0 7f 9e eb 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=5
 
}