
rule Virus_Win32_Waltrodock_A{
	meta:
		description = "Virus:Win32/Waltrodock.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {9c e8 01 00 00 00 ?? 83 c4 04 60 e8 14 00 00 00 ?? ?? ?? ?? ?? ff d1 61 9d ff 15 ?? ?? ?? ?? e9 ?? ?? ?? ?? 58 e8 e6 ff ff ff 62 64 63 61 70 45 78 33 32 2e 64 6c 6c } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}