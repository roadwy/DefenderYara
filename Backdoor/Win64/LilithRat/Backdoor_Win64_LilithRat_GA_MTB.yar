
rule Backdoor_Win64_LilithRat_GA_MTB{
	meta:
		description = "Backdoor:Win64/LilithRat.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 0b 00 00 "
		
	strings :
		$a_80_0 = {6b 65 79 64 75 6d 70 } //keydump  1
		$a_80_1 = {6b 65 79 6c 6f 67 2e 74 78 74 } //keylog.txt  1
		$a_80_2 = {6c 6f 67 2e 74 78 74 } //log.txt  1
		$a_80_3 = {72 65 6d 6f 74 65 43 6f 6e 74 72 6f 6c } //remoteControl  1
		$a_80_4 = {63 6f 6d 6d 61 6e 64 } //command  1
		$a_80_5 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 } //powershell.exe  1
		$a_80_6 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 } //GetAsyncKeyState  1
		$a_80_7 = {5b 4c 4d 4f 55 53 45 5d } //[LMOUSE]  1
		$a_80_8 = {52 65 73 74 61 72 74 20 72 65 71 75 65 73 74 65 64 3a 20 52 65 73 74 61 72 74 69 6e 67 20 73 65 6c 66 } //Restart requested: Restarting self  1
		$a_80_9 = {54 65 72 6d 69 6e 61 74 69 6f 6e 20 72 65 71 75 65 73 74 65 64 3a 20 4b 69 6c 6c 69 6e 67 20 73 65 6c 66 } //Termination requested: Killing self  1
		$a_80_10 = {43 6f 75 6c 64 6e 27 74 20 77 72 69 74 65 20 74 6f 20 43 4d 44 3a 20 43 4d 44 20 6e 6f 74 20 6f 70 65 } //Couldn't write to CMD: CMD not ope  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1) >=9
 
}