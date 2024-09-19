
rule Trojan_BAT_SnakeKeylogger_SML_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 76 61 73 63 6f 63 6f 72 72 65 74 6f 72 61 2e 63 6f 6d 2e 62 72 2f 50 50 49 2f } //1 https://www.vascocorretora.com.br/PPI/
		$a_81_1 = {47 65 74 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //1 GetByteArrayAsync
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}