
rule Trojan_Win32_TrickBot_O_bit{
	meta:
		description = "Trojan:Win32/TrickBot.O!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 8b c2 66 8b 10 42 42 81 fa 4f 5a 00 00 74 11 2d 00 00 01 00 66 8b 10 42 81 fa 4e 5a 00 00 75 ef 8b f8 e9 06 2f fd ff } //1
		$a_01_1 = {8b 54 24 18 8b 74 24 14 8b 4c 24 10 8b 7c 24 0c 85 d2 74 0e 52 ac 30 07 5a 47 4a e2 f3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}