
rule Ransom_Win64_Filecoder_BMX_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.BMX!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 65 6e 64 69 6e 67 20 65 6e 63 72 79 70 74 69 6f 6e 20 6b 65 79 73 20 74 6f 20 54 65 6c 65 67 72 61 6d } //1 Sending encryption keys to Telegram
		$a_01_1 = {66 69 6c 65 73 20 74 6f 20 65 6e 63 72 79 70 74 } //1 files to encrypt
		$a_01_2 = {54 00 65 00 6c 00 65 00 67 00 72 00 61 00 6d 00 20 00 42 00 6f 00 74 00 20 00 43 00 6c 00 69 00 65 00 6e 00 74 00 } //1 Telegram Bot Client
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}