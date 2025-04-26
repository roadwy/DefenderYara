
rule Trojan_Win64_GoKrypt_AC_MTB{
	meta:
		description = "Trojan:Win64/GoKrypt.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //2 Go build ID:
		$a_01_1 = {54 63 79 41 6b 71 68 34 6f 4a 58 67 56 33 57 59 79 4c 34 4b 45 66 43 4d 6b 39 57 38 6f 4a 43 70 6d 78 31 62 6f 2b 6a 56 67 4b 59 3d } //2 TcyAkqh4oJXgV3WYyL4KEfCMk9W8oJCpmx1bo+jVgKY=
		$a_01_2 = {55 44 52 62 6f 74 54 4f 4d 74 6b 75 66 37 54 54 4a 51 50 69 53 56 6a 64 52 5a 71 55 6d 69 31 6f 47 65 35 66 55 73 32 68 4c 77 77 3d } //2 UDRbotTOMtkuf7TTJQPiSVjdRZqUmi1oGe5fUs2hLww=
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}
rule Trojan_Win64_GoKrypt_AC_MTB_2{
	meta:
		description = "Trojan:Win64/GoKrypt.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 89 e7 fc f3 48 a5 48 89 e6 48 8b 0e 48 8b 56 08 4c 8b 46 10 4c 8b 4e 18 66 48 0f 6e c1 66 48 0f 6e ca 66 49 0f 6e d0 66 49 0f 6e d9 ff d0 } //1
		$a_01_1 = {47 6f 20 62 75 69 6c 64 69 6e 66 3a } //1 Go buildinf:
		$a_01_2 = {32 35 38 45 41 46 41 35 2d 45 39 31 34 2d 34 37 44 41 2d 39 35 43 41 2d 43 35 41 42 30 44 43 38 35 42 31 31 } //1 258EAFA5-E914-47DA-95CA-C5AB0DC85B11
		$a_01_3 = {48 6a 4d 57 5a 34 79 36 6b 43 2e 6b 4c 79 6a 41 49 58 6b 59 61 39 6b } //1 HjMWZ4y6kC.kLyjAIXkYa9k
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}