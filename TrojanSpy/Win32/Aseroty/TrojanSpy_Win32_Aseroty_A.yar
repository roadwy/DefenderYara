
rule TrojanSpy_Win32_Aseroty_A{
	meta:
		description = "TrojanSpy:Win32/Aseroty.A,SIGNATURE_TYPE_CMDHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_00_0 = {73 00 63 00 2e 00 65 00 78 00 65 00 20 00 63 00 72 00 65 00 61 00 74 00 65 00 } //1 sc.exe create
		$a_00_1 = {73 00 63 00 20 00 63 00 72 00 65 00 61 00 74 00 65 00 } //1 sc create
		$a_02_2 = {62 00 69 00 6e 00 50 00 61 00 74 00 68 00 3d 00 90 02 f0 61 00 73 00 77 00 61 00 72 00 70 00 6f 00 74 00 2e 00 73 00 79 00 73 00 90 00 } //20
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*20) >=21
 
}