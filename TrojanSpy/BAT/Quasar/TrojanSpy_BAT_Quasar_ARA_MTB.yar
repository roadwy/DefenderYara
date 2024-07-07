
rule TrojanSpy_BAT_Quasar_ARA_MTB{
	meta:
		description = "TrojanSpy:BAT/Quasar.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 42 75 66 66 65 72 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 4d 69 63 68 61 65 6c 2e 70 64 62 } //2 \Buffer\obj\Release\Michael.pdb
		$a_80_1 = {65 77 6a 75 66 68 75 72 65 75 72 65 67 74 69 68 } //ewjufhureuregtih  2
		$a_01_2 = {24 63 65 66 36 35 38 39 38 2d 34 37 62 36 2d 34 33 64 32 2d 62 34 34 31 2d 30 37 66 33 63 64 39 63 32 37 65 34 } //2 $cef65898-47b6-43d2-b441-07f3cd9c27e4
	condition:
		((#a_01_0  & 1)*2+(#a_80_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}