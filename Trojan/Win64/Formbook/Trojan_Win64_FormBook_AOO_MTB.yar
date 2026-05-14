
rule Trojan_Win64_FormBook_AOO_MTB{
	meta:
		description = "Trojan:Win64/FormBook.AOO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 4d a0 32 4c 15 b8 88 4c 15 e8 48 ff c2 48 83 fa 10 } //2
		$a_01_1 = {66 03 ff 66 46 89 0c 30 66 46 89 44 30 02 8d 57 02 0f b7 45 af 4e 89 14 30 0f b7 45 b1 66 42 89 3c 30 66 42 89 54 30 02 0f b7 45 b3 4a 89 1c 30 49 8b 04 37 49 8b 0c 04 } //3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}