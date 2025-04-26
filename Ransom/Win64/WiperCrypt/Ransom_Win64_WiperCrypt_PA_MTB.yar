
rule Ransom_Win64_WiperCrypt_PA_MTB{
	meta:
		description = "Ransom:Win64/WiperCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 76 69 63 6f } //1 .vico
		$a_01_1 = {54 00 65 00 6c 00 65 00 67 00 72 00 61 00 6d 00 20 00 42 00 6f 00 74 00 20 00 43 00 6c 00 69 00 65 00 6e 00 74 00 } //1 Telegram Bot Client
		$a_01_2 = {5c 63 61 73 65 5f 69 64 2e 74 78 74 } //1 \case_id.txt
		$a_01_3 = {59 4f 55 52 20 46 49 4c 45 53 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 } //1 YOUR FILES HAVE BEEN ENCRYPTED
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}