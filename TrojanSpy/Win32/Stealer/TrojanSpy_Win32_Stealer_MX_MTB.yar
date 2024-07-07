
rule TrojanSpy_Win32_Stealer_MX_MTB{
	meta:
		description = "TrojanSpy:Win32/Stealer.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {c1 ea 05 03 95 90 01 04 89 95 90 01 04 3d 31 09 00 00 90 00 } //1
		$a_02_1 = {81 f3 07 eb dd 13 81 6d 90 01 01 52 ef 6f 62 2d f3 32 05 00 81 6d 90 01 01 68 19 2a 14 81 45 90 01 01 be 08 9a 76 8b 45 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}