
rule PWS_Win32_Zbot_TV{
	meta:
		description = "PWS:Win32/Zbot.TV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 04 88 66 83 38 2d 0f 85 ?? ?? ?? ?? 8d 78 02 6a 3a 57 ff 15 ?? ?? ?? ?? 80 7d 14 00 } //1
		$a_03_1 = {6a 05 58 6a 04 66 89 45 ?? 58 53 66 89 45 ?? 6a 05 8d 45 ?? 50 57 c6 45 ?? 02 ff d6 83 f8 05 } //1
		$a_01_2 = {42 00 61 00 63 00 6b 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 20 00 53 00 65 00 72 00 76 00 65 00 72 00 } //1 Backconnect Server
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}