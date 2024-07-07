
rule Backdoor_Win32_Ixeshe_H_dha{
	meta:
		description = "Backdoor:Win32/Ixeshe.H!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c6 d1 0f 6b 9f d9 49 fc 90 02 50 4d 69 63 72 6f 73 6f 66 74 20 45 6e 68 61 6e 63 65 64 20 43 72 79 70 74 6f 67 72 61 70 68 69 63 20 50 72 6f 76 69 64 65 72 20 76 31 2e 30 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}