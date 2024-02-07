
rule Trojan_BAT_RedLine_RDBE_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 58 6b 44 62 } //01 00  EXkDb
		$a_01_1 = {30 31 72 74 69 } //01 00  01rti
		$a_01_2 = {30 30 6d 56 50 } //01 00  00mVP
		$a_01_3 = {4e 00 47 00 2f 00 59 00 71 00 4d 00 70 00 69 00 35 00 4d 00 5a 00 6d 00 34 00 4c 00 } //01 00  NG/YqMpi5MZm4L
		$a_01_4 = {4f 00 71 00 2b 00 32 00 6e 00 45 00 6e 00 64 00 36 00 55 00 } //01 00  Oq+2nEnd6U
		$a_01_5 = {35 00 72 00 32 00 44 00 42 00 48 00 76 00 65 00 73 00 42 00 35 00 32 00 4b 00 39 00 39 00 35 00 35 00 59 00 3d 00 } //00 00  5r2DBHvesB52K9955Y=
	condition:
		any of ($a_*)
 
}