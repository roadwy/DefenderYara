
rule TrojanDropper_Win32_Delf_BL_MTB{
	meta:
		description = "TrojanDropper:Win32/Delf.BL!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {c7 45 f8 01 00 00 00 8b 45 fc 8b 55 f8 8a 5c 10 ff 80 f3 0a 8d 45 f4 8b d3 e8 } //02 00 
		$a_01_1 = {6d 70 63 7a 26 2a 6e 6f 6c 66 6b 7e 6f } //01 00  mpcz&*nolfk~o
		$a_01_2 = {25 63 64 6e 6f 72 25 6d 6f 7e 69 6c 6d 35 63 6e 37 } //01 00  %cdnor%mo~ilm5cn7
		$a_01_3 = {2f 69 6e 64 65 78 2f 67 65 74 63 66 67 3f 69 64 3d } //00 00  /index/getcfg?id=
		$a_01_4 = {00 67 16 } //00 00 
	condition:
		any of ($a_*)
 
}