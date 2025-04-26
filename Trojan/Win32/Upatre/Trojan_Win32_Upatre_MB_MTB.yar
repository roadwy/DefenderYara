
rule Trojan_Win32_Upatre_MB_MTB{
	meta:
		description = "Trojan:Win32/Upatre.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 08 8a 0c 08 8b 54 24 04 88 0c 10 40 3b 44 24 0c 72 eb } //1
		$a_01_1 = {56 53 56 ff 75 fc 68 4c 21 40 00 56 ff 15 } //1
		$a_01_2 = {62 00 75 00 6c 00 6b 00 62 00 61 00 63 00 6b 00 6c 00 69 00 6e 00 6b 00 73 00 2e 00 63 00 6f 00 6d 00 } //1 bulkbacklinks.com
		$a_01_3 = {68 00 75 00 6d 00 6d 00 79 00 2e 00 65 00 78 00 65 00 } //1 hummy.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}