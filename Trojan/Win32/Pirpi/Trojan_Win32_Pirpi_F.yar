
rule Trojan_Win32_Pirpi_F{
	meta:
		description = "Trojan:Win32/Pirpi.F,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {75 4b 8b 4d 08 8b 55 0c 8b 44 8a fc 0f be 08 83 f9 74 75 39 8b 55 08 8b 45 0c 8b 4c 90 fc 0f be 51 01 83 fa 35 75 26 } //1
		$a_01_1 = {81 f9 0f 27 00 00 7e 23 b8 ad 8b db 68 f7 e9 c1 fa 0c 8b c2 c1 e8 1f 03 d0 8b c1 8b fa b9 10 27 00 00 99 f7 f9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}