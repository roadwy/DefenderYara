
rule Backdoor_Win32_Votwup_D{
	meta:
		description = "Backdoor:Win32/Votwup.D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 65 73 75 6c 74 2e 64 61 72 6b } //1 result.dark
		$a_01_1 = {54 45 52 4d 53 52 56 2f 2a } //1 TERMSRV/*
		$a_03_2 = {3f 75 69 64 3d 00 90 01 0a 26 76 65 72 3d 00 90 00 } //1
		$a_03_3 = {62 63 00 00 90 01 08 43 52 55 53 48 00 90 00 } //1
		$a_01_4 = {68 74 74 70 3a 2f 2f 00 64 61 72 6b 6e 65 73 73 } //1 瑨灴⼺/慤歲敮獳
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}