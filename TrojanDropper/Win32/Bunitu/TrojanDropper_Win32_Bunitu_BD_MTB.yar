
rule TrojanDropper_Win32_Bunitu_BD_MTB{
	meta:
		description = "TrojanDropper:Win32/Bunitu.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 ea 03 89 15 90 01 04 a1 90 01 04 2b 05 90 01 04 a3 90 01 04 8b 0d 90 01 04 03 0d 90 01 04 89 0d 90 01 04 83 3d 90 01 04 00 0f 85 90 00 } //1
		$a_00_1 = {81 e9 09 b5 00 00 51 c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}