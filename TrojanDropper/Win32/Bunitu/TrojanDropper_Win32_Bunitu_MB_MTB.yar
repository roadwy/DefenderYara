
rule TrojanDropper_Win32_Bunitu_MB_MTB{
	meta:
		description = "TrojanDropper:Win32/Bunitu.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d8 33 d9 8b ff c7 05 90 01 08 8b db 01 1d 90 01 04 a1 90 01 04 8b 0d 90 01 04 89 08 5f 5b 5d c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}