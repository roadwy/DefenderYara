
rule Trojan_Win64_GoKrypt_DW_MTB{
	meta:
		description = "Trojan:Win64/GoKrypt.DW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 ed 30 9e 20 2a dc 17 a9 1c 6c 9f c5 99 bf 62 28 33 71 78 1a 79 be 97 66 f2 1c 7a 70 db 30 52 96 65 1d 95 52 27 16 } //1
		$a_01_1 = {08 0a 20 f1 c0 11 8a 15 7c b4 b9 d4 8b 3f 1d 31 7c 08 d5 1d 4a 40 ed 13 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}