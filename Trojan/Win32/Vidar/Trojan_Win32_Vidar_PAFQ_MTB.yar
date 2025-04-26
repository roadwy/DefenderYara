
rule Trojan_Win32_Vidar_PAFQ_MTB{
	meta:
		description = "Trojan:Win32/Vidar.PAFQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 75 fc ff 75 0c 03 f7 ff 15 ?? ?? ?? ?? 8b c8 8b 45 fc 33 d2 f7 f1 8b 45 0c 8b 4d f8 8a 04 02 32 04 31 ff 45 fc 88 06 39 5d fc 72 d3 } //2
		$a_00_1 = {53 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 46 00 72 00 6f 00 6d 00 20 00 41 00 6e 00 74 00 69 00 56 00 69 00 72 00 75 00 73 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 } //2 Select * From AntiVirusProduct
		$a_01_2 = {5c 44 69 73 63 6f 72 64 5c 74 6f 6b 65 6e 73 2e 74 78 74 } //1 \Discord\tokens.txt
		$a_01_3 = {6c 6f 67 69 6e 75 73 65 72 73 2e 76 64 66 } //2 loginusers.vdf
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=7
 
}