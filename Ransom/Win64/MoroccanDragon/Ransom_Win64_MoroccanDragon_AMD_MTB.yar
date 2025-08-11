
rule Ransom_Win64_MoroccanDragon_AMD_MTB{
	meta:
		description = "Ransom:Win64/MoroccanDragon.AMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 06 00 00 "
		
	strings :
		$a_03_0 = {48 8d 0d 21 4b 00 00 e8 ?? ?? ?? ?? 48 89 c3 48 85 c0 74 ?? 48 89 c2 48 89 e9 e8 ?? ?? ?? ?? 48 89 d9 e8 ?? ?? ?? ?? 48 8d 0d 06 4b } //6
		$a_01_1 = {53 65 6e 64 69 6e 67 20 65 6e 63 72 79 70 74 69 6f 6e 20 6b 65 79 73 20 74 6f 20 54 65 6c 65 67 72 61 6d } //1 Sending encryption keys to Telegram
		$a_01_2 = {54 00 65 00 6c 00 65 00 67 00 72 00 61 00 6d 00 20 00 42 00 6f 00 74 00 20 00 43 00 6c 00 69 00 65 00 6e 00 74 00 } //2 Telegram Bot Client
		$a_01_3 = {61 00 70 00 69 00 2e 00 74 00 65 00 6c 00 65 00 67 00 72 00 61 00 6d 00 2e 00 6f 00 72 00 67 00 } //3 api.telegram.org
		$a_01_4 = {2e 76 69 63 6f } //5 .vico
		$a_01_5 = {63 61 73 65 5f 69 64 2e 74 78 74 } //4 case_id.txt
	condition:
		((#a_03_0  & 1)*6+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*3+(#a_01_4  & 1)*5+(#a_01_5  & 1)*4) >=21
 
}