
rule TrojanDownloader_Win32_Sinresby_B{
	meta:
		description = "TrojanDownloader:Win32/Sinresby.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 26 6b 3d 00 26 6f 3d 00 26 43 3d 00 26 75 3d 00 26 64 3d 00 26 76 3d 00 6d 3d 00 3f } //1
		$a_01_1 = {53 65 6c 65 63 74 20 4d 41 43 41 64 64 72 65 73 73 20 46 72 6f 6d 20 57 69 6e 33 32 5f 4e 65 74 77 6f 72 6b 41 64 61 70 74 65 72 20 57 48 45 52 45 20 50 4e 50 44 65 76 69 63 65 49 44 20 4c 49 4b 45 20 22 25 50 43 49 25 } //1 Select MACAddress From Win32_NetworkAdapter WHERE PNPDeviceID LIKE "%PCI%
		$a_01_2 = {62 6c 61 63 6b 6d 6f 6f 6e 00 } //1 汢捡浫潯n
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}