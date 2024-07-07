
rule Trojan_Win32_Peglegmorb_A{
	meta:
		description = "Trojan:Win32/Peglegmorb.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {bb 1a 7c e8 02 00 eb fe 60 8a 07 3c 00 74 09 b4 0e cd 10 83 c3 01 eb f1 61 c3 } //4
		$a_01_1 = {53 4f 4d 45 54 48 49 4e 47 20 48 41 53 20 4f 56 45 52 57 52 49 54 54 45 4e 20 59 4f 55 52 20 4d 42 52 21 } //2 SOMETHING HAS OVERWRITTEN YOUR MBR!
		$a_01_2 = {bb 00 20 40 00 ba 80 00 00 00 89 c7 89 de 89 d1 f3 a5 } //2
		$a_01_3 = {c7 44 24 10 00 00 00 00 8d 45 e0 89 44 24 0c c7 44 24 08 00 02 00 00 8d 85 e0 fd ff ff 89 44 24 04 8b 45 e4 89 04 24 e8 } //2
		$a_01_4 = {50 45 47 47 4c 45 43 52 45 57 } //1 PEGGLECREW
		$a_01_5 = {28 40 43 55 4c 54 4f 46 52 41 5a 45 52 20 4f 4e 20 54 57 49 54 54 45 52 29 } //1 (@CULTOFRAZER ON TWITTER)
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}