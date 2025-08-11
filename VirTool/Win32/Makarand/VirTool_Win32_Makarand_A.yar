
rule VirTool_Win32_Makarand_A{
	meta:
		description = "VirTool:Win32/Makarand.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {61 32 56 79 62 6d 56 73 4d 7a 49 75 5a 47 78 73 } //1 a2VybmVsMzIuZGxs
		$a_81_1 = {62 6e 52 6b 62 47 77 75 5a 47 78 73 } //1 bnRkbGwuZGxs
		$a_81_2 = {54 47 39 68 5a 45 78 70 59 6e 4a 68 63 6e 6c 42 } //1 TG9hZExpYnJhcnlB
		$a_81_3 = {52 32 56 30 55 48 4a 76 59 30 46 6b 5a 48 4a 6c 63 33 4d } //1 R2V0UHJvY0FkZHJlc3M
		$a_81_4 = {56 6d 6c 79 64 48 56 68 62 46 42 79 62 33 52 6c 59 33 51 } //1 VmlydHVhbFByb3RlY3Q
		$a_81_5 = {59 57 31 7a 61 53 35 6b 62 47 77 } //1 YW1zaS5kbGw
		$a_81_6 = {51 57 31 7a 61 56 4e 6a 59 57 35 43 64 57 5a 6d 5a 58 49 } //1 QW1zaVNjYW5CdWZmZXI
		$a_81_7 = {52 58 52 33 52 58 5a 6c 62 6e 52 58 63 6d 6c 30 5a 51 } //1 RXR3RXZlbnRXcml0ZQ
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}