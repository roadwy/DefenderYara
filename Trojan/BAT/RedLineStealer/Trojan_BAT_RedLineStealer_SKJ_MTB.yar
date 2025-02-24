
rule Trojan_BAT_RedLineStealer_SKJ_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.SKJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {19 8d 4e 00 00 01 25 16 0f 01 28 26 00 00 0a 9c 25 17 0f 01 28 27 00 00 0a 9c 25 18 0f 01 28 28 00 00 0a 9c 0b 02 07 04 28 02 00 00 2b 6f 2b 00 00 0a 2a } //1
		$a_00_1 = {16 0a 2b 0e 02 03 04 06 05 28 0b 00 00 06 06 17 58 0a 06 02 28 08 00 00 06 2f 09 03 6f 2e 00 00 0a 05 32 e0 } //1
		$a_81_2 = {6c 62 6c 42 72 6f 6a 50 6f 67 6f 64 61 6b 61 } //1 lblBrojPogodaka
		$a_81_3 = {46 6c 75 65 6e 74 4c 6f 67 34 4e 65 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 FluentLog4Net.Properties.Resources
		$a_81_4 = {4c 4f 54 4f 5f 61 70 6c 69 6b 61 63 69 6a 61 2e 46 72 6d 4c 6f 74 6f 2e 72 65 73 6f 75 72 63 65 73 } //1 LOTO_aplikacija.FrmLoto.resources
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}