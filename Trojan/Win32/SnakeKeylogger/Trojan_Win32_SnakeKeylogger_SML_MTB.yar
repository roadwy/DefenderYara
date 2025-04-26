
rule Trojan_Win32_SnakeKeylogger_SML_MTB{
	meta:
		description = "Trojan:Win32/SnakeKeylogger.SML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {61 6f 72 74 6f 67 72 61 70 68 69 63 } //1 aortographic
		$a_81_1 = {66 6c 6f 72 69 6b 65 6e } //1 floriken
		$a_81_2 = {62 69 6c 69 6f 75 73 6e 65 73 73 65 73 2e 65 78 65 } //1 biliousnesses.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}
rule Trojan_Win32_SnakeKeylogger_SML_MTB_2{
	meta:
		description = "Trojan:Win32/SnakeKeylogger.SML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {69 72 61 73 63 65 6e 74 20 66 6f 72 6c 61 67 73 6c 65 64 65 72 65 6e } //1 irascent forlagslederen
		$a_81_1 = {61 70 70 6c 69 63 72 63 72 20 63 65 72 76 69 63 6f 74 68 6f 72 61 63 69 63 20 70 61 72 61 6d 65 74 65 72 6c 69 73 74 65 72 6e 65 73 } //1 applicrcr cervicothoracic parameterlisternes
		$a_81_2 = {70 61 72 61 64 69 63 68 6c 6f 72 62 65 6e 7a 6f 6c 20 6b 72 79 64 73 65 72 65 73 2e 65 78 65 } //1 paradichlorbenzol krydseres.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}