
rule Trojan_BAT_NanoBot_S_MTB{
	meta:
		description = "Trojan:BAT/NanoBot.S!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {24 35 63 64 63 31 63 37 36 2d 38 39 39 63 2d 34 36 39 65 2d 39 37 61 66 2d 61 38 63 36 30 66 38 36 31 64 35 65 } //1 $5cdc1c76-899c-469e-97af-a8c60f861d5e
		$a_81_1 = {6c 79 4d 43 36 3d 33 5f } //1 lyMC6=3_
		$a_81_2 = {43 59 27 30 21 4c 6b } //1 CY'0!Lk
		$a_81_3 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
		$a_00_4 = {57 15 02 08 09 03 00 00 00 fa 01 33 00 16 00 00 } //1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}