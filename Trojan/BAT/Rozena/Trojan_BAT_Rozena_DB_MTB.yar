
rule Trojan_BAT_Rozena_DB_MTB{
	meta:
		description = "Trojan:BAT/Rozena.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {13 08 16 13 10 2b 17 11 08 11 10 11 08 11 10 91 20 fa 00 00 00 61 d2 9c 11 10 17 58 13 10 11 10 11 08 8e 69 32 e1 } //10
		$a_81_1 = {58 4f 52 2d 64 65 63 6f 64 65 64 20 70 61 79 6c 6f 61 64 } //1 XOR-decoded payload
		$a_81_2 = {43 72 65 61 74 65 20 6e 65 77 20 70 72 6f 63 65 73 73 20 67 72 61 62 62 65 72 } //1 Create new process grabber
	condition:
		((#a_01_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=12
 
}