
rule Trojan_Win32_Zenpak_NZ_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {48 59 67 61 74 68 65 72 65 64 36 77 69 6e 67 65 64 2e 6d 61 6c 65 6d 61 64 65 66 4e 79 } //1 HYgathered6winged.malemadefNy
		$a_01_1 = {6d 65 61 74 69 6c 69 76 69 6e 67 64 61 79 49 62 65 } //1 meatilivingdayIbe
		$a_01_2 = {6c 57 68 61 6c 65 73 6d 61 6b 65 46 71 61 62 75 6e 64 61 6e 74 6c 79 2e 61 6d 75 6c 74 69 70 6c 79 47 } //1 lWhalesmakeFqabundantly.amultiplyG
		$a_01_3 = {4a 6c 69 67 68 74 66 69 66 74 68 37 73 68 65 2e 64 } //1 Jlightfifth7she.d
		$a_01_4 = {67 61 74 68 65 72 65 64 6f 6e 65 37 45 6b 69 6e 64 } //1 gatheredone7Ekind
		$a_01_5 = {63 61 6e 2e 74 2c 37 66 6c 79 } //1 can.t,7fly
		$a_01_6 = {64 72 79 61 6c 6c 73 69 67 6e 73 4d 6c 69 76 69 6e 67 } //1 dryallsignsMliving
		$a_01_7 = {73 68 65 2e 64 62 72 6f 75 67 68 74 69 } //1 she.dbroughti
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}