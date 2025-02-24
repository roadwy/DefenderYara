
rule Trojan_BAT_FormBook_NOD_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NOD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_81_0 = {64 62 39 37 37 38 32 62 2d 31 39 37 61 2d 34 33 33 35 2d 38 36 38 61 2d 35 31 61 65 39 65 65 38 37 65 62 63 } //2 db97782b-197a-4335-868a-51ae9ee87ebc
		$a_81_1 = {55 62 69 78 2e 42 6c 61 63 6b 4a 61 63 6b } //1 Ubix.BlackJack
		$a_81_2 = {49 4c 6f 67 67 65 72 } //1 ILogger
		$a_81_3 = {43 6f 6e 73 6f 6c 65 4c 6f 67 67 65 72 } //1 ConsoleLogger
		$a_81_4 = {53 71 6c 44 62 42 61 63 6b 41 6e 64 52 65 73 74 6f 72 65 } //1 SqlDbBackAndRestore
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=6
 
}