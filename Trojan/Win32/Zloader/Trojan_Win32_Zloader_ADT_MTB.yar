
rule Trojan_Win32_Zloader_ADT_MTB{
	meta:
		description = "Trojan:Win32/Zloader.ADT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 03 00 00 "
		
	strings :
		$a_01_0 = {fe 45 ff 0f b6 75 ff 8a 14 06 00 55 fe 0f b6 4d fe 8a 1c 01 88 1c 06 88 14 01 0f b6 34 06 8b 4d 08 0f b6 d2 03 f2 81 e6 ff 00 00 00 8a 14 06 30 14 39 47 3b 7d 0c 72 c8 } //20
		$a_80_1 = {48 54 54 50 2f 31 2e 31 } //HTTP/1.1  1
		$a_80_2 = {45 42 57 41 6b 56 53 45 4c 4a 65 49 59 50 51 49 45 } //EBWAkVSELJeIYPQIE  1
	condition:
		((#a_01_0  & 1)*20+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=22
 
}