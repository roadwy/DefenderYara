
rule Trojan_Win32_GuLoader_SWD_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SWD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {61 61 6c 68 6f 6c 6d 73 2e 65 78 65 } //1 aalholms.exe
		$a_81_1 = {76 69 64 72 69 6b 73 20 6c 75 6d 73 6b 65 72 69 20 63 6f 69 66 66 65 75 72 73 } //1 vidriks lumskeri coiffeurs
		$a_81_2 = {66 6f 64 65 72 76 69 6b 6b 65 72 73 20 67 65 6e 6f 70 72 65 74 74 65 20 6f 62 65 6c 75 73 } //1 fodervikkers genoprette obelus
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}