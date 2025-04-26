
rule TrojanSpy_Win32_Festeal_C{
	meta:
		description = "TrojanSpy:Win32/Festeal.C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {84 c9 74 0f 80 f9 40 74 26 8a 48 01 83 c0 01 0e 75 f1 80 38 fd fd 8f fd 17 33 c0 8b 8c 29 33 cc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}