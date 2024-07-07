
rule Backdoor_MacOS_Fegrat_C_dha{
	meta:
		description = "Backdoor:MacOS/Fegrat.C!dha,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {52 65 64 46 6c 61 72 65 2f 72 61 74 2f 6d 6f 64 75 6c 65 73 2f 6e 65 74 73 77 65 65 70 65 72 2e 28 2a 50 69 6e 67 65 72 29 2e 43 6c 6f 73 65 } //1 RedFlare/rat/modules/netsweeper.(*Pinger).Close
		$a_00_1 = {52 65 64 46 6c 61 72 65 2f 72 61 74 2f 6d 6f 64 75 6c 65 73 2f 6e 65 74 73 77 65 65 70 65 72 2e 65 78 70 65 63 74 65 64 4e 65 74 73 77 65 65 70 65 72 41 72 67 73 } //1 RedFlare/rat/modules/netsweeper.expectedNetsweeperArgs
		$a_00_2 = {52 65 64 46 6c 61 72 65 2f 72 61 74 2f 70 6c 61 74 66 6f 72 6d 73 2f 64 61 72 77 69 6e 2e 28 2a 64 61 72 77 69 6e 41 67 65 6e 74 29 2e 44 65 73 74 72 6f 79 } //1 RedFlare/rat/platforms/darwin.(*darwinAgent).Destroy
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}