
rule Trojan_BAT_SnakeKeylogger_SML_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {4e 66 6c 7a 70 74 75 6d 6d 71 } //1 Nflzptummq
		$a_81_1 = {24 61 30 33 66 31 35 37 36 2d 38 35 38 30 2d 34 65 64 35 2d 39 32 35 32 2d 30 62 38 31 37 32 38 34 38 38 65 38 } //1 $a03f1576-8580-4ed5-9252-0b81728488e8
		$a_00_2 = {06 07 a3 02 00 00 01 28 05 00 00 06 dd 06 00 00 00 } //1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule Trojan_BAT_SnakeKeylogger_SML_MTB_2{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 76 61 73 63 6f 63 6f 72 72 65 74 6f 72 61 2e 63 6f 6d 2e 62 72 2f 50 50 49 2f } //1 https://www.vascocorretora.com.br/PPI/
		$a_81_1 = {47 65 74 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //1 GetByteArrayAsync
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}