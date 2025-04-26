
rule Trojan_Win64_AsyncRat_BSA_MTB{
	meta:
		description = "Trojan:Win64/AsyncRat.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 48 83 ec 20 48 8d 6c 24 20 48 8b 09 0f b6 d2 e8 af 68 06 00 83 f8 ff 74 08 31 c0 48 83 c4 20 5d } //10
		$a_01_1 = {31 d2 e8 bf 5c 06 00 48 8b 36 e8 8b 51 06 00 48 89 f1 89 c2 49 89 f8 e8 6e 4d 06 00 83 f8 ff 0f 84 98 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=10
 
}