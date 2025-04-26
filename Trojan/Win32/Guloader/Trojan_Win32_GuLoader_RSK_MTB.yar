
rule Trojan_Win32_GuLoader_RSK_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {75 6e 73 74 72 61 69 67 68 74 65 6e 65 64 5c 75 6e 70 72 65 64 69 63 61 62 6c 65 5c 6b 6f 6e 73 74 61 6e 63 65 } //1 unstraightened\unpredicable\konstance
		$a_81_1 = {5c 64 79 6e 65 6c 66 74 65 72 6e 65 5c 66 72 65 6d 6d 65 64 70 6f 6c 69 74 69 73 2e 41 66 6b } //1 \dynelfterne\fremmedpolitis.Afk
		$a_81_2 = {25 6b 61 6a 70 6c 61 64 73 65 72 6e 65 25 5c 63 6f 72 64 69 65 73 5c 70 61 72 74 69 63 69 70 65 72 65 6e 64 65 73 2e 41 6e 6e } //1 %kajpladserne%\cordies\participerendes.Ann
		$a_81_3 = {35 5c 53 6e 65 73 70 75 72 76 65 2e 4d 79 73 } //1 5\Snespurve.Mys
		$a_81_4 = {5c 62 72 65 61 74 68 61 6c 79 7a 65 5c 61 64 75 6c 74 73 2e 6c 6f 63 } //1 \breathalyze\adults.loc
		$a_81_5 = {23 5c 44 69 73 61 6c 6c 6f 77 61 6e 63 65 32 33 32 5c 2a 2e 76 65 6a } //1 #\Disallowance232\*.vej
		$a_81_6 = {62 75 73 73 65 72 6f 6e 6e 65 2e 69 6e 69 } //1 busseronne.ini
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}