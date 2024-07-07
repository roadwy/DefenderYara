
rule Trojan_Win32_Nanocore_GPD_MTB{
	meta:
		description = "Trojan:Win32/Nanocore.GPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {10 57 63 b6 81 1f 47 5d 10 57 63 b6 81 1f 47 5d 41 55 33 21 45 41 30 36 4d a8 ff 73 24 a7 3c f6 7a 12 f1 67 ac c1 93 e7 6b 43 ca 52 a6 ad } //5
		$a_01_1 = {88 8b 98 9b 3a 24 44 10 88 8b 98 9b 3a 24 44 10 41 55 33 21 45 41 30 36 4d a8 ff 73 24 a7 3c f6 7a 12 f1 67 ac c1 93 e7 6b 43 ca 52 a6 ad } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=5
 
}