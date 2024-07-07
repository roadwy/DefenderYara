
rule TrojanSpy_Win32_StealBit_A{
	meta:
		description = "TrojanSpy:Win32/StealBit.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 61 73 73 77 6f 72 64 00 00 00 00 53 54 41 54 49 43 00 00 45 44 49 54 00 00 00 00 4f 4b 00 00 42 55 54 54 4f 4e 00 00 43 61 6e 63 65 6c 00 90 01 01 45 00 6e 00 74 00 65 00 72 00 20 00 79 00 6f 00 75 00 72 00 20 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}