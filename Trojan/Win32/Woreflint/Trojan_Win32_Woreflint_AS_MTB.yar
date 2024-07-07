
rule Trojan_Win32_Woreflint_AS_MTB{
	meta:
		description = "Trojan:Win32/Woreflint.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0c 00 04 00 00 "
		
	strings :
		$a_02_0 = {11 04 17 58 20 00 01 00 00 5d 13 04 11 05 07 11 04 91 58 20 00 01 00 00 5d 13 05 07 11 04 91 90 01 01 07 11 04 07 11 05 91 9c 07 11 05 09 9c 07 11 04 91 07 11 05 91 58 20 00 01 00 00 90 00 } //10
		$a_80_1 = {5b 41 4d 49 4e 45 5d } //[AMINE]  5
		$a_80_2 = {43 3a 5c 55 73 65 72 73 5c 6d 61 64 61 72 5c } //C:\Users\madar\  4
		$a_80_3 = {42 42 42 42 32 } //BBBB2  3
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*5+(#a_80_2  & 1)*4+(#a_80_3  & 1)*3) >=12
 
}