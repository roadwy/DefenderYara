
rule TrojanSpy_Win32_Noon_MD_MTB{
	meta:
		description = "TrojanSpy:Win32/Noon.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 64 24 00 8a 91 90 01 04 30 90 01 05 83 f9 90 01 01 75 90 01 01 33 c9 eb 90 01 01 41 40 3b c6 72 90 01 01 8d 90 01 02 50 6a 90 01 01 56 68 90 01 04 ff 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}