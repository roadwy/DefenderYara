
rule Trojan_Win32_QakBot_MV_MTB{
	meta:
		description = "Trojan:Win32/QakBot.MV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {89 08 5f 5d c3 90 0a 28 00 8b 90 02 05 33 90 02 05 8b 90 01 01 89 15 90 02 04 a1 90 02 04 8b 0d 90 00 } //2
		$a_01_1 = {63 00 3a 00 5c 00 6d 00 69 00 72 00 63 00 5c 00 6d 00 69 00 72 00 63 00 2e 00 69 00 6e 00 69 00 } //1 c:\mirc\mirc.ini
		$a_01_2 = {43 00 3a 00 5c 00 4d 00 69 00 72 00 63 00 5c 00 6d 00 69 00 72 00 63 00 2e 00 69 00 6e 00 69 00 } //1 C:\Mirc\mirc.ini
	condition:
		((#a_02_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}