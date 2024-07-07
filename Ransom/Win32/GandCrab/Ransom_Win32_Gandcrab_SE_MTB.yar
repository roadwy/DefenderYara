
rule Ransom_Win32_Gandcrab_SE_MTB{
	meta:
		description = "Ransom:Win32/Gandcrab.SE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 56 33 f6 57 8b f8 39 75 08 7e 20 6a 00 ff 15 90 01 04 ff 15 90 01 04 e8 90 01 04 30 84 3e 00 fe ff ff 46 3b 75 08 7c e0 5f 5e 5d c2 04 00 90 00 } //1
		$a_03_1 = {8a 8c 37 32 09 00 00 a1 90 01 04 88 0c 30 83 fe 90 01 01 75 28 68 90 01 04 6a 40 ff 74 24 14 50 ff 15 90 01 04 89 5c 24 18 c7 44 24 18 20 00 00 00 8b 44 24 18 03 c0 89 44 24 18 46 3b 74 24 0c 72 97 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}