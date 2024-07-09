
rule TrojanDropper_Win32_Odrtre_B{
	meta:
		description = "TrojanDropper:Win32/Odrtre.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {0f 00 c0 09 c0 75 } //1
		$a_02_1 = {81 c4 00 01 00 00 be ?? ?? 40 00 ad 83 f8 01 0f 84 2d 01 00 00 83 f8 02 0f 84 cc 00 00 00 83 f8 03 74 2c } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}