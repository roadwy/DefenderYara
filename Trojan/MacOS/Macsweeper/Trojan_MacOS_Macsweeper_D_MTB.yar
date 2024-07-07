
rule Trojan_MacOS_Macsweeper_D_MTB{
	meta:
		description = "Trojan:MacOS/Macsweeper.D!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 75 72 63 68 61 69 73 65 54 68 72 65 61 64 3a } //3 purchaiseThread:
		$a_00_1 = {63 6f 6d 2e 69 4d 75 6e 69 7a 61 74 6f 72 2e 69 4d 75 6e 69 7a 61 74 6f 72 } //1 com.iMunizator.iMunizator
		$a_02_2 = {69 6d 75 6e 69 7a 61 74 6f 72 2e 90 02 03 2f 62 75 79 2e 70 68 70 90 00 } //1
		$a_00_3 = {63 6f 6d 2e 4b 49 56 56 69 53 6f 66 74 77 61 72 65 2e 4d 61 63 53 77 65 65 70 65 72 44 61 65 6d 6f 6e } //1 com.KIVViSoftware.MacSweeperDaemon
		$a_02_4 = {6d 61 63 73 77 65 65 70 65 72 2e 90 02 03 2f 62 75 79 2e 70 68 70 90 00 } //1
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1) >=5
 
}