
rule Ransom_Win32_Rensen_A_rsm{
	meta:
		description = "Ransom:Win32/Rensen.A!rsm,SIGNATURE_TYPE_PEHSTR_EXT,ffffff90 01 ffffff90 01 04 00 00 "
		
	strings :
		$a_01_0 = {2e 00 52 00 45 00 4e 00 53 00 45 00 4e 00 57 00 41 00 52 00 45 00 } //100 .RENSENWARE
		$a_01_1 = {4e 00 4f 00 54 00 20 00 4c 00 55 00 4e 00 41 00 54 00 49 00 43 00 20 00 4c 00 45 00 56 00 45 00 4c 00 } //100 NOT LUNATIC LEVEL
		$a_01_2 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //100 ReadProcessMemory
		$a_01_3 = {54 00 48 00 31 00 32 00 20 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 53 00 74 00 61 00 74 00 75 00 73 00 } //100 TH12 Process Status
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100+(#a_01_3  & 1)*100) >=400
 
}