
rule TrojanDownloader_Win32_Satacom_FV_MTB{
	meta:
		description = "TrojanDownloader:Win32/Satacom.FV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e4 8b 08 8b 45 e8 8b 10 8b 45 e8 8b 00 c1 e0 06 89 c3 8b 45 e8 8b 00 c1 e8 08 31 d8 8d 1c 02 8b 45 f0 ba 00 00 00 00 f7 75 dc 89 d0 8d 14 85 00 00 00 00 8b 45 0c 01 d0 8b 00 } //10
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}