
rule TrojanDropper_Win32_Vundo_E{
	meta:
		description = "TrojanDropper:Win32/Vundo.E,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {36 35 2e 32 34 74 33 37 31 30 08 be 9f e8 bd c0 24 3f 63 6d 70 3d 74 76 c3 9c 6b 5f 75 cb 64 37 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}