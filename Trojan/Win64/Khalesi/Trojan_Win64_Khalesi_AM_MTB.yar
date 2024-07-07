
rule Trojan_Win64_Khalesi_AM_MTB{
	meta:
		description = "Trojan:Win64/Khalesi.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b 55 77 81 e9 ce 00 00 00 44 8b 45 07 41 03 d4 44 8b 4d ff 41 81 e8 1f 08 00 00 8b 75 7f 41 81 e9 b6 06 00 00 8b 7d 03 81 c6 f3 09 00 00 8b 5d fb 03 f8 44 8b 5d ff 81 eb dc 06 00 00 44 8b 55 03 41 81 eb 13 06 00 00 } //10
		$a_01_1 = {4b 72 72 51 46 57 47 59 57 4e } //3 KrrQFWGYWN
	condition:
		((#a_00_0  & 1)*10+(#a_01_1  & 1)*3) >=13
 
}