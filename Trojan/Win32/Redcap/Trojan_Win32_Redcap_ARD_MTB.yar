
rule Trojan_Win32_Redcap_ARD_MTB{
	meta:
		description = "Trojan:Win32/Redcap.ARD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 40 52 57 50 88 5e 0a ff 15 ?? ?? ?? ?? 8b 8c 24 28 02 00 00 6a 00 55 56 8b 35 6c 00 41 00 57 51 ff d6 8b 84 24 28 02 00 00 6a 00 8d 94 24 84 02 00 00 68 30 01 00 00 52 53 50 } //3
		$a_01_1 = {8b 06 33 c9 89 44 24 24 8a 4c 24 27 33 d2 83 c6 04 8a 54 24 26 8b 0c 8d ec 38 41 00 33 0c 95 ec 3c 41 00 33 d2 8a d4 25 ff 00 00 00 33 0c 95 ec 40 41 00 8b 14 85 ec 44 41 00 33 ca 4f } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}