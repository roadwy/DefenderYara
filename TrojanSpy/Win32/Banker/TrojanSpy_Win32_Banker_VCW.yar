
rule TrojanSpy_Win32_Banker_VCW{
	meta:
		description = "TrojanSpy:Win32/Banker.VCW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 50 6c 41 70 70 6c 65 74 00 46 6f 78 69 74 52 65 61 64 65 72 2e 63 70 6c 00 } //1
		$a_01_1 = {54 00 41 00 50 00 50 00 41 00 44 00 4d 00 49 00 4e 00 49 00 53 00 54 00 52 00 41 00 44 00 4f 00 52 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}