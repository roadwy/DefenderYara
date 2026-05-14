
rule Backdoor_BAT_PulsarRat_MK_MTB{
	meta:
		description = "Backdoor:BAT/PulsarRat.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 04 00 00 "
		
	strings :
		$a_03_0 = {35 00 70 72 ?? ?? 00 70 11 05 72 ?? ?? 00 70 28 ?? ?? 00 0a 73 ?? ?? 00 0a 13 06 11 06 16 6f ?? ?? 00 0a 11 06 17 6f ?? ?? 00 0a 11 06 17 6f ?? 00 00 0a 07 } //25
		$a_81_1 = {52 55 4e 4e 45 52 5f 55 52 4c } //10 RUNNER_URL
		$a_81_2 = {2d 4e 6f 50 72 6f 66 69 6c 65 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 45 6e 63 6f 64 65 64 43 6f 6d 6d 61 6e 64 } //3 -NoProfile -ExecutionPolicy Bypass -EncodedCommand
		$a_81_3 = {2d 4e 6f 50 72 6f 66 69 6c 65 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 46 69 6c 65 } //2 -NoProfile -ExecutionPolicy Bypass -File
	condition:
		((#a_03_0  & 1)*25+(#a_81_1  & 1)*10+(#a_81_2  & 1)*3+(#a_81_3  & 1)*2) >=40
 
}