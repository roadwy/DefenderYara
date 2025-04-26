
rule TrojanSpy_Win32_Hitpop_AM{
	meta:
		description = "TrojanSpy:Win32/Hitpop.AM,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 6e 65 78 65 00 } //1 湦硥e
		$a_01_1 = {6d 79 64 6f 77 6e 00 } //1
		$a_01_2 = {6f 6c 64 5f 65 78 65 00 } //1 汯彤硥e
		$a_01_3 = {66 6e 5f 64 6c 6c 00 } //1
		$a_03_4 = {68 ff 00 00 00 6a 0c 8b 45 f8 50 e8 ?? ?? ff ff 6a 01 6a 0d 68 00 01 00 00 } //3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*3) >=5
 
}