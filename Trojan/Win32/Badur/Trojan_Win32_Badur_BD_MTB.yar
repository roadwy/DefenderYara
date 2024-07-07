
rule Trojan_Win32_Badur_BD_MTB{
	meta:
		description = "Trojan:Win32/Badur.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {83 c4 08 8a 10 8b 44 24 18 8a 08 03 d1 81 e2 ff 00 00 80 79 08 4a 81 ca 00 ff ff ff 42 8b 44 24 20 81 e2 ff 00 00 00 8a 0c 32 8a 14 03 32 d1 88 14 03 8b 44 24 24 43 3b d8 0f } //1
		$a_01_1 = {5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //1 \shell\open\command
		$a_01_2 = {75 70 64 61 74 65 2e 74 78 74 } //1 update.txt
		$a_01_3 = {5c 53 79 73 74 65 6d 52 6f 6f 74 } //1 \SystemRoot
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}