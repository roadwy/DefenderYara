
rule TrojanDownloader_Win32_Doina_ARA_MTB{
	meta:
		description = "TrojanDownloader:Win32/Doina.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 03 30 e0 88 03 43 e2 f7 } //2
		$a_80_1 = {47 6c 6f 62 61 6c 5c 55 52 31 34 37 47 57 6d 73 } //Global\UR147GWms  2
	condition:
		((#a_01_0  & 1)*2+(#a_80_1  & 1)*2) >=4
 
}