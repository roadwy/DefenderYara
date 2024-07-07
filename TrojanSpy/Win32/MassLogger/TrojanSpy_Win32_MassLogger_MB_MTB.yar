
rule TrojanSpy_Win32_MassLogger_MB_MTB{
	meta:
		description = "TrojanSpy:Win32/MassLogger.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 18 80 f3 90 01 01 8b fa 03 fe 88 1f 8b da 03 de 80 33 90 01 01 46 40 49 75 e9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}