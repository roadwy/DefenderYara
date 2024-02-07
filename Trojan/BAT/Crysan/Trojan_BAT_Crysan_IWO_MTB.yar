
rule Trojan_BAT_Crysan_IWO_MTB{
	meta:
		description = "Trojan:BAT/Crysan.IWO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 00 74 00 75 00 64 00 65 00 6e 00 74 00 43 00 61 00 6c 00 63 00 75 00 6c 00 61 00 74 00 65 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //01 00  StudentCalculate.Resources
		$a_01_1 = {42 00 49 00 47 00 5f 00 44 00 49 00 53 00 43 00 4f 00 52 00 44 00 5f 00 4c 00 49 00 4e 00 4b 00 5f 00 53 00 54 00 52 00 49 00 4e 00 47 00 } //01 00  BIG_DISCORD_LINK_STRING
		$a_01_2 = {6d 00 65 00 6d 00 62 00 65 00 72 00 74 00 6f 00 69 00 6e 00 76 00 6f 00 6b 00 65 00 } //01 00  membertoinvoke
		$a_01_3 = {6d 00 61 00 6b 00 6d 00 61 00 6c 00 20 00 79 00 61 00 6e 00 67 00 20 00 64 00 69 00 70 00 65 00 72 00 6c 00 75 00 6b 00 61 00 6e 00 } //01 00  makmal yang diperlukan
		$a_01_4 = {42 00 74 00 6e 00 43 00 61 00 6c 00 63 00 75 00 6c 00 61 00 74 00 65 00 } //01 00  BtnCalculate
		$a_01_5 = {6c 00 62 00 6c 00 4a 00 75 00 6d 00 6c 00 61 00 68 00 4d 00 61 00 6b 00 6d 00 61 00 6c 00 } //01 00  lblJumlahMakmal
		$a_01_6 = {4a 00 75 00 6d 00 6c 00 61 00 68 00 50 00 65 00 6c 00 61 00 6a 00 61 00 72 00 } //01 00  JumlahPelajar
		$a_81_7 = {4e 52 5f 77 6b 64 6f 71 77 6b 64 6f 71 77 6b 64 71 } //01 00  NR_wkdoqwkdoqwkdq
		$a_81_8 = {73 65 74 5f 45 78 70 65 63 74 31 30 30 43 6f 6e 74 69 6e 75 65 } //01 00  set_Expect100Continue
		$a_81_9 = {4e 52 5f 42 6f 73 74 6f 72 6f 74 68 } //01 00  NR_Bostoroth
		$a_81_10 = {67 65 74 5f 6c 62 6c 4a 75 6d 6c 61 68 4d 61 6b 6d 61 6c } //00 00  get_lblJumlahMakmal
	condition:
		any of ($a_*)
 
}