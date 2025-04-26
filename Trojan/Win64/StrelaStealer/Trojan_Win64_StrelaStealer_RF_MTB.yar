
rule Trojan_Win64_StrelaStealer_RF_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {6f 75 74 2e 64 6c 6c 00 68 65 6c 6c 6f } //5
		$a_01_1 = {79 7a 78 6d 4a 78 69 43 65 70 7a 41 47 74 79 44 77 65 73 6a 4d 65 6f 78 54 59 65 6f 76 4f 63 56 79 6d 72 6e 48 64 75 } //1 yzxmJxiCepzAGtyDwesjMeoxTYeovOcVymrnHdu
		$a_01_2 = {43 77 50 45 59 51 44 74 69 6f 6a 68 62 66 50 44 54 65 4c 65 76 6d 64 75 54 74 62 4a 4a 5a 49 42 6e 6e 63 6b 4a 5a 77 53 62 5a 71 65 41 41 } //1 CwPEYQDtiojhbfPDTeLevmduTtbJJZIBnnckJZwSbZqeAA
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}