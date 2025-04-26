
rule Trojan_Win32_Netwire_PR_MTB{
	meta:
		description = "Trojan:Win32/Netwire.PR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b c6 83 e0 03 0f b6 54 05 fc 30 94 35 18 fd ff ff 8d 7c 05 fc 8b c1 83 e0 03 8d 54 05 fc 0f b6 02 30 84 35 19 fd ff ff 8d 41 fe 8d 58 ff 83 e3 03 8a 5c 1d fc 30 9c 35 1a fd ff ff 83 e0 03 0f b6 44 05 fc 30 84 35 1b fd ff ff 0f b6 07 30 84 35 1c fd ff ff 0f b6 12 30 94 35 1d fd ff ff 83 c1 06 83 c6 06 81 f9 e3 02 00 00 72 93 } //1
		$a_01_1 = {8a 4d fe 8a 5d ff 8a d0 8a c4 34 2c 80 f2 df 80 f1 33 80 f3 35 3c 14 75 0e 80 f9 01 75 09 80 fa e9 75 04 84 db 74 09 8b 45 fc 40 89 45 fc eb d0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}