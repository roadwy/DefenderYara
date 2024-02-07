
rule TrojanSpy_AndroidOS_Teardroid_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Teardroid.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 65 78 61 6d 70 6c 65 2e 74 65 61 72 64 72 6f 69 64 76 32 } //01 00  com.example.teardroidv2
		$a_00_1 = {67 65 74 56 69 63 74 69 6d 49 44 } //01 00  getVictimID
		$a_01_2 = {54 65 61 72 64 72 6f 69 64 } //01 00  Teardroid
		$a_00_3 = {77 65 62 68 6f 6f 6b 2e 73 69 74 65 2f 64 65 37 39 39 65 30 63 2d 64 61 39 30 2d 34 34 33 38 2d 61 66 33 38 2d 37 32 32 37 63 31 63 66 62 36 63 32 } //01 00  webhook.site/de799e0c-da90-4438-af38-7227c1cfb6c2
		$a_00_4 = {72 75 6e 73 68 65 6c 6c } //01 00  runshell
		$a_00_5 = {6d 61 6b 65 63 61 6c 6c } //01 00  makecall
		$a_00_6 = {67 65 74 63 6f 6e 74 61 63 74 } //01 00  getcontact
		$a_00_7 = {67 65 74 73 6d 73 } //00 00  getsms
		$a_00_8 = {5d 04 00 00 84 } //09 05 
	condition:
		any of ($a_*)
 
}