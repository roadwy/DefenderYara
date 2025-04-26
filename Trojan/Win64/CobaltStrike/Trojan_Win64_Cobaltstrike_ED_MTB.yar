
rule Trojan_Win64_Cobaltstrike_ED_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_81_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //10 DllRegisterServer
		$a_81_1 = {73 61 6a 6d 67 68 6e 6d 62 7a 61 75 2e 64 6c 6c } //1 sajmghnmbzau.dll
		$a_81_2 = {61 71 78 76 70 62 68 68 65 6b 71 6c 75 7a 6d 6d 74 } //1 aqxvpbhhekqluzmmt
		$a_81_3 = {62 6b 79 62 79 6e 72 76 6f 74 62 77 6c 6a 6e } //1 bkybynrvotbwljn
		$a_81_4 = {63 77 61 63 72 78 6d 7a 6b 6b 71 6e 6d 75 } //1 cwacrxmzkkqnmu
		$a_81_5 = {66 64 72 79 70 63 64 70 72 6e 72 6a 72 6f 71 78 71 } //1 fdrypcdprnrjroqxq
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=15
 
}