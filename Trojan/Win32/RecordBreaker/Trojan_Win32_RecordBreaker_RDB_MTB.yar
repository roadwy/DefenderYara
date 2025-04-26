
rule Trojan_Win32_RecordBreaker_RDB_MTB{
	meta:
		description = "Trojan:Win32/RecordBreaker.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 00 6f 00 6c 00 64 00 6f 00 76 00 61 00 } //1 Moldova
		$a_01_1 = {6b 65 72 6e 65 6c 33 32 2e 64 6c 6c } //1 kernel32.dll
		$a_01_2 = {74 69 6d 65 47 65 74 54 69 6d 65 } //1 timeGetTime
		$a_01_3 = {57 44 41 47 55 74 69 6c 69 74 79 41 63 63 6f 75 6e 74 } //1 WDAGUtilityAccount
		$a_01_4 = {c6 45 b8 61 c6 45 b9 67 c6 45 ba 6a c6 45 bb 76 c6 45 bc 33 c6 45 bd 76 c6 45 be 33 c6 45 bf 6a c6 45 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2) >=6
 
}