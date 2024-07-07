
rule Trojan_Win32_Adept_C{
	meta:
		description = "Trojan:Win32/Adept.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {50 78 2e 41 78 00 } //3 硐䄮x
		$a_01_1 = {0f b6 d0 33 da 8b 45 0c 8b 08 8b 55 fc 88 1c 11 eb c8 } //2
		$a_01_2 = {6a 02 6a 00 6a fb } //1
		$a_01_3 = {eb d1 8b 45 08 03 45 fc 0f b6 08 8b 45 fc 99 f7 7d 14 8b 45 10 0f b6 14 10 33 ca 8b 45 08 03 45 fc 88 08 } //2
	condition:
		((#a_00_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=5
 
}