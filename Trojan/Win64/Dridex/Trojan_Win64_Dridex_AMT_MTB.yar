
rule Trojan_Win64_Dridex_AMT_MTB{
	meta:
		description = "Trojan:Win64/Dridex.AMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_00_0 = {ef c0 f3 0f 7f 44 24 70 66 0f 6e ca 99 66 0f 62 d1 f3 0f 7f 94 24 80 00 00 00 66 0f 6e da 66 0f 62 e3 f3 0f 7f a4 24 90 } //10
		$a_80_1 = {41 64 64 4c 6f 6f 6b 61 73 69 64 65 } //AddLookaside  3
		$a_80_2 = {43 72 65 61 74 65 44 65 73 6b 74 6f 70 41 70 70 58 41 63 74 69 76 61 74 69 6f 6e 49 6e 66 6f } //CreateDesktopAppXActivationInfo  3
		$a_80_3 = {34 63 48 30 33 } //4cH03  3
		$a_80_4 = {43 6c 6f 73 65 41 70 70 45 78 65 63 75 74 69 6f 6e 41 6c 69 61 73 } //CloseAppExecutionAlias  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=22
 
}