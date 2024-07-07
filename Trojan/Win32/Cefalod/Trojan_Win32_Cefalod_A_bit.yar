
rule Trojan_Win32_Cefalod_A_bit{
	meta:
		description = "Trojan:Win32/Cefalod.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 76 6d 70 32 00 00 00 } //10
		$a_01_1 = {61 64 6f 70 6c 61 79 2e 78 63 6d 2e 69 63 61 66 65 38 2e 6e 65 74 } //10 adoplay.xcm.icafe8.net
		$a_01_2 = {51 00 51 00 5f 00 54 00 53 00 45 00 48 00 5f 00 46 00 4c 00 41 00 47 00 5f 00 25 00 64 00 } //10 QQ_TSEH_FLAG_%d
		$a_01_3 = {00 71 71 2e 65 78 65 00 } //1
		$a_01_4 = {44 52 52 00 5c 5c 2e 5c 70 69 70 65 5c 53 57 4e 54 72 61 63 65 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=32
 
}