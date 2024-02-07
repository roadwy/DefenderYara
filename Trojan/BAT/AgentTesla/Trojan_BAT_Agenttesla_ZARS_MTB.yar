
rule Trojan_BAT_Agenttesla_ZARS_MTB{
	meta:
		description = "Trojan:BAT/Agenttesla.ZARS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 65 67 69 6e 52 65 61 64 } //01 00  BeginRead
		$a_01_1 = {69 73 44 69 73 63 6f 6e 6e 65 63 74 65 64 } //01 00  isDisconnected
		$a_01_2 = {42 65 67 69 6e 52 65 63 65 69 76 65 } //01 00  BeginReceive
		$a_01_3 = {41 45 53 5f 44 65 63 72 79 70 74 6f 72 } //01 00  AES_Decryptor
		$a_01_4 = {41 45 53 5f 45 6e 63 72 79 70 74 6f 72 } //01 00  AES_Encryptor
		$a_01_5 = {53 68 6f 74 } //01 00  Shot
		$a_01_6 = {52 65 61 64 } //00 00  Read
	condition:
		any of ($a_*)
 
}