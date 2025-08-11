
rule Trojan_Win32_Heracles_ARAX_MTB{
	meta:
		description = "Trojan:Win32/Heracles.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {24 30 37 63 61 63 30 34 39 2d 61 32 33 38 2d 34 35 66 32 2d 39 31 39 36 2d 30 64 62 66 31 63 34 39 32 39 35 62 } //2 $07cac049-a238-45f2-9196-0dbf1c49295b
		$a_01_1 = {73 76 63 68 6f 73 74 2e 4c 6f 67 69 6e 2e 72 65 73 6f 75 72 63 65 73 } //2 svchost.Login.resources
		$a_01_2 = {73 76 63 68 6f 73 74 2e 73 76 63 68 6f 73 74 2e 72 65 73 6f 75 72 63 65 73 } //2 svchost.svchost.resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}