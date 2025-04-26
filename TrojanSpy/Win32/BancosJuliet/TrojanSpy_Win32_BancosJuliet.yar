
rule TrojanSpy_Win32_BancosJuliet{
	meta:
		description = "TrojanSpy:Win32/BancosJuliet,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 00 4a 00 75 00 6c 00 69 00 65 00 74 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 } //1 \Juliet\Desktop
		$a_01_1 = {5c 00 42 00 48 00 4f 00 42 00 4a 00 5c 00 66 00 6c 00 61 00 73 00 68 00 } //1 \BHOBJ\flash
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}