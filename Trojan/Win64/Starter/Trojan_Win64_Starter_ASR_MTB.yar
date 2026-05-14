
rule Trojan_Win64_Starter_ASR_MTB{
	meta:
		description = "Trojan:Win64/Starter.ASR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 8b f8 33 c0 b9 08 02 00 00 f3 aa 4c 8d 4d 30 4c 8d 05 dd 97 00 00 ba 04 01 00 00 48 8d 8d 60 02 00 00 } //1
		$a_01_1 = {48 8b f8 33 c0 b9 00 fa 00 00 f3 aa 4c 8d 8d 60 02 00 00 4c 8d 05 ca 97 00 00 ba 00 7d 00 00 48 8d 8d 90 04 00 00 } //2
		$a_01_2 = {48 8b f8 33 c0 b9 fc 7f 00 00 f3 aa 4c 8d 05 6e 9c 00 00 ba fe 3f 00 00 48 8d 8d b0 fe 00 00 } //3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3) >=6
 
}