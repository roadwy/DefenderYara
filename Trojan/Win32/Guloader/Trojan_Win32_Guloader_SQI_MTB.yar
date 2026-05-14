
rule Trojan_Win32_Guloader_SQI_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SQI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_81_0 = {62 6c 6f 6d 73 74 65 72 68 61 6e 64 6c 65 72 65 2e 70 6f 64 } //2 blomsterhandlere.pod
		$a_81_1 = {4d 6f 72 66 6f 72 6c 64 72 65 73 34 30 2e 65 6e 67 } //1 Morforldres40.eng
		$a_81_2 = {48 6f 6e 73 68 75 5c 75 6e 6d 61 72 72 69 6e 67 } //1 Honshu\unmarring
		$a_81_3 = {45 6e 63 65 6c 6c 65 64 65 31 33 32 5c 52 65 65 6e 74 65 72 65 64 35 33 } //1 Encellede132\Reentered53
		$a_81_4 = {62 61 63 68 65 6c 6f 72 69 7a 65 73 5c 66 6f 72 75 64 62 65 73 74 65 6d } //1 bachelorizes\forudbestem
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=6
 
}