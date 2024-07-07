
rule Trojan_Win32_Reconyc_dwuq_MTB{
	meta:
		description = "Trojan:Win32/Reconyc.dwuq!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 "
		
	strings :
		$a_02_0 = {31 e1 83 ea 01 52 ff 0c 24 5a c1 ea 05 c1 ea 08 81 e2 90 01 04 81 f2 90 01 04 89 d1 89 c8 90 00 } //10
		$a_81_1 = {54 4a 70 72 6f 6a 4d 61 69 6e 2e 65 78 65 } //2 TJprojMain.exe
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*2) >=12
 
}