
rule Trojan_BAT_FileCoder_SM_MTB{
	meta:
		description = "Trojan:BAT/FileCoder.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 09 94 0b 07 16 32 16 07 02 6f 3a 00 00 0a 2f 0d 06 02 07 6f 3b 00 00 0a 6f 3c 00 00 0a 09 17 58 0d 09 08 8e 69 32 d8 } //2
		$a_81_1 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 73 74 6f 6c 65 6e 20 61 6e 64 20 65 6e 63 72 79 70 74 65 64 } //2 All your files are stolen and encrypted
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}