
rule Virus_Win32_Expiro_AEX_MTB{
	meta:
		description = "Virus:Win32/Expiro.AEX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 83 24 02 00 00 74 7a 35 0c f7 93 24 01 00 00 81 83 8c 03 00 00 ff 74 aa 09 81 b3 e0 01 00 00 9a 6b aa 32 81 b3 38 02 00 00 cd 41 5a 63 81 ab e4 00 00 00 ce 46 82 1f 81 ab fc 00 00 00 91 44 39 28 81 b3 d8 03 00 00 0a 13 e7 57 81 ab 7c 02 00 00 cf 4b 75 30 81 b3 b4 00 00 00 51 0c 29 32 81 83 dc 03 00 00 6b 7b d8 1f 81 83 c4 00 00 00 f1 59 98 77 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}