
rule Trojan_Win32_Remcos_ARR_MTB{
	meta:
		description = "Trojan:Win32/Remcos.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3f 4d 42 4d 32 83 c4 04 81 cb ab 36 01 00 5b } //1
		$a_01_1 = {57 81 f7 bc ba 00 00 81 cf 8c c8 00 00 81 e7 06 6f 01 00 5f 57 57 83 c4 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}