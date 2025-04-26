
rule Trojan_Win32_Phorpiex_SIB_MTB{
	meta:
		description = "Trojan:Win32/Phorpiex.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2e 00 21 00 06 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 67 6f 74 73 6f 6d 65 66 69 6c 65 2e 74 6f 70 2f } //10 http://gotsomefile.top/
		$a_00_1 = {68 74 74 70 3a 2f 2f 66 65 65 64 6d 65 66 69 6c 65 2e 74 6f 70 2f } //10 http://feedmefile.top/
		$a_00_2 = {68 74 74 70 3a 2f 2f 67 69 6d 6d 65 66 69 6c 65 2e 74 6f 70 2f } //10 http://gimmefile.top/
		$a_00_3 = {68 74 74 70 3a 2f 2f 74 73 72 76 33 2e 72 75 2f } //10 http://tsrv3.ru/
		$a_00_4 = {25 00 6c 00 73 00 3a 00 5a 00 6f 00 6e 00 65 00 2e 00 49 00 64 00 65 00 6e 00 74 00 69 00 66 00 69 00 65 00 72 00 } //3 %ls:Zone.Identifier
		$a_03_5 = {8d 55 f4 52 e8 ?? ?? ?? ?? 83 c4 04 39 45 f0 73 1d 8b 45 f0 0f be 4c 05 f4 8b 55 08 03 55 fc 0f be 02 33 c1 8b 4d 08 03 4d fc 88 01 eb c9 } //3
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*3+(#a_03_5  & 1)*3) >=33
 
}