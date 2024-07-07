
rule Trojan_Win32_Injector_B{
	meta:
		description = "Trojan:Win32/Injector.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 c4 f8 8b c8 33 d2 89 55 f8 89 4d fc 8b 45 fc 03 45 f8 89 c7 80 37 90 01 01 90 90 42 81 fa 90 01 02 00 00 75 e5 59 59 5d 90 00 } //1
		$a_01_1 = {6f 6d 6a 42 36 45 4e 31 31 4c 76 38 52 51 55 73 72 38 58 5a 53 66 6c 68 68 } //1 omjB6EN11Lv8RQUsr8XZSflhh
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}