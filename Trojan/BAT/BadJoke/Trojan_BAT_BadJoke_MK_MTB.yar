
rule Trojan_BAT_BadJoke_MK_MTB{
	meta:
		description = "Trojan:BAT/BadJoke.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,46 00 46 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 75 6d 70 69 6e 67 20 70 68 79 73 69 63 61 6c 20 6d 65 6d 6f 72 79 20 74 6f 20 64 69 73 6b 3a 20 40 70 } //20 Dumping physical memory to disk: @p
		$a_01_1 = {2d 2d 64 75 6d 70 73 74 61 72 74 54 } //15 --dumpstartT
		$a_01_2 = {2d 2d 64 75 6d 70 70 72 6f 67 72 65 73 73 5b } //15 --dumpprogress[
		$a_01_3 = {5d 41 20 70 72 6f 62 6c 65 6d 20 68 61 73 20 62 65 65 6e 20 64 65 74 65 63 74 65 64 20 61 6e 64 20 77 69 6e 64 6f 77 73 20 68 61 73 20 62 65 65 6e 20 73 68 75 74 64 6f 77 6e 20 74 6f 20 70 72 65 76 65 6e 74 20 64 61 6d 61 67 65 20 74 6f 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 2e } //10 ]A problem has been detected and windows has been shutdown to prevent damage to your computer.
		$a_01_4 = {28 53 74 6f 70 20 63 6f 64 65 3a 20 44 52 49 56 45 52 5f 49 52 51 4c 5f 4e 4f 54 5f 4c 45 53 53 5f 4f 52 5f 45 51 55 41 4c } //10 (Stop code: DRIVER_IRQL_NOT_LESS_OR_EQUAL
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*15+(#a_01_2  & 1)*15+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10) >=70
 
}