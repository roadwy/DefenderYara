
rule Ransom_Win64_FileCoder_RHAE_MTB{
	meta:
		description = "Ransom:Win64/FileCoder.RHAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_03_0 = {50 45 00 00 64 86 0f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 03 00 00 ?? 24 00 00 ?? 03 00 00 00 00 00 ?? ?? 06 } //2
		$a_01_1 = {65 6e 63 72 79 70 74 54 69 63 6b 65 74 } //3 encryptTicket
		$a_01_2 = {59 6f 75 72 20 64 61 74 61 20 68 61 73 20 62 65 65 6e 20 73 74 6f 6c 65 6e 20 61 6e 64 20 65 6e 63 72 79 70 74 65 64 } //2 Your data has been stolen and encrypted
		$a_01_3 = {2e 62 61 63 6b 75 70 2e 77 61 6c 6c 65 74 2e 6f 6e 65 70 6b 67 2e 63 6f 6e 66 69 67 2e 74 61 72 } //1 .backup.wallet.onepkg.config.tar
		$a_01_4 = {5c 55 4e 43 } //1 \UNC
		$a_01_5 = {68 61 6e 67 75 70 6b 69 6c 6c 65 64 } //1 hangupkilled
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}