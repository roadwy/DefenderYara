
rule Trojan_BAT_Sunilla_A_dha{
	meta:
		description = "Trojan:BAT/Sunilla.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {33 35 31 33 63 61 36 66 2d 65 33 39 32 2d 34 30 66 33 2d 39 36 35 62 2d 39 64 34 61 66 37 66 64 34 30 34 30 } //5 3513ca6f-e392-40f3-965b-9d4af7fd4040
		$a_01_1 = {43 68 61 70 65 72 6f 6e 65 53 65 72 76 69 63 65 4d 6f 6e 69 74 6f 72 } //2 ChaperoneServiceMonitor
		$a_01_2 = {4d 61 69 6e 74 50 6f 6c 2e 64 6c 6c } //2 MaintPol.dll
		$a_03_3 = {50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 [0-05] 4d 00 61 00 69 00 6e 00 74 00 65 00 6e 00 61 00 6e 00 63 00 65 00 20 00 50 00 6f 00 6c 00 69 00 63 00 79 00 } //2
		$a_01_4 = {43 68 65 63 6b 52 65 6d 6f 76 65 44 61 74 65 } //1 CheckRemoveDate
		$a_01_5 = {53 65 74 53 65 72 76 69 63 65 52 65 67 69 73 74 72 79 } //1 SetServiceRegistry
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_03_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}