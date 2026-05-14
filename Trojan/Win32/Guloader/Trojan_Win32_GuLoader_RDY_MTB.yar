
rule Trojan_Win32_GuLoader_RDY_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RDY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {41 66 74 6a 65 6e 69 6e 67 65 72 73 5c 61 6e 6d 65 6c 64 65 6c 73 65 73 70 6c 69 67 74 65 72 5c 62 6f 6c 69 67 73 65 6c 73 6b 61 62 65 72 73 } //1 Aftjeningers\anmeldelsespligter\boligselskabers
		$a_81_1 = {69 6e 74 6f 6c 65 72 61 6e 63 65 73 5c 67 6c 75 74 65 6c 69 6e 73 5c 63 68 72 6f 6e 6f 6c 6f 67 79 } //1 intolerances\glutelins\chronology
		$a_81_2 = {5c 57 68 61 6e 67 65 65 73 31 37 5c 4e 65 64 66 6c 64 6e 69 6e 67 65 6e 32 31 34 } //1 \Whangees17\Nedfldningen214
		$a_81_3 = {25 50 61 72 63 65 6c 6c 69 73 74 25 5c 50 61 6c 65 72 6d 69 74 61 6e 5c 55 6e 70 72 6f 74 65 63 74 } //1 %Parcellist%\Palermitan\Unprotect
		$a_81_4 = {5c 44 69 6b 74 65 72 65 72 2e 68 74 6d } //1 \Dikterer.htm
		$a_81_5 = {5c 74 72 76 6c 65 72 6f 64 65 6e 73 5c 69 64 65 6d 2e 65 78 65 } //1 \trvlerodens\idem.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}