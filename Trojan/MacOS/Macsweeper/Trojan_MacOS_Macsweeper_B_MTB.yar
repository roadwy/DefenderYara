
rule Trojan_MacOS_Macsweeper_B_MTB{
	meta:
		description = "Trojan:MacOS/Macsweeper.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {69 4d 75 6e 69 7a 61 74 6f 72 43 4d 49 3a 20 54 72 79 69 6e 67 20 74 6f 20 64 65 6c 65 74 65 20 66 69 6c 65 73 } //1 iMunizatorCMI: Trying to delete files
		$a_00_1 = {6f 70 65 6e 20 2d 61 20 69 4d 75 6e 69 7a 61 74 6f 72 44 61 65 6d 6f 6e } //1 open -a iMunizatorDaemon
		$a_00_2 = {63 6f 6d 2e 69 4d 75 6e 69 7a 61 74 6f 72 2e 69 4d 75 6e 69 7a 61 74 6f 72 44 61 65 6d 6f 6e } //1 com.iMunizator.iMunizatorDaemon
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}