
rule Trojan_Win32_CobaltStrike_DBA_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.DBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {35 9d 33 00 00 50 8d 81 ee fc ff ff 50 8b 44 24 48 56 05 0d 0e 00 00 50 ff 74 24 64 8d 81 a0 01 00 00 50 8d 87 7b ec ff ff 81 f7 7f 2e 00 00 50 8d 81 aa 08 00 00 50 57 e8 ef 19 01 00 8b 44 24 58 83 c4 30 35 36 32 } //4
		$a_01_1 = {59 6e 4a 52 45 32 38 32 42 39 } //1 YnJRE282B9
		$a_01_2 = {4b 76 72 51 49 33 36 43 39 46 } //1 KvrQI36C9F
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}