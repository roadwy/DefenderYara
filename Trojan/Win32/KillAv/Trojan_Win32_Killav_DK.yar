
rule Trojan_Win32_Killav_DK{
	meta:
		description = "Trojan:Win32/Killav.DK,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 0f be 00 85 c0 74 ?? 8b 45 fc 0f be 00 83 f8 7c 75 06 8b 45 fc c6 00 00 8b 45 fc 40 } //1
		$a_01_1 = {50 6a 00 6a 00 6a 04 8d 45 ec 50 68 08 20 22 00 ff 75 08 ff 15 } //1
		$a_01_2 = {6a 00 8d 45 fc 50 6a 04 ff 75 10 6a 04 8d 45 0c 50 68 4b 21 22 00 ff 75 08 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}