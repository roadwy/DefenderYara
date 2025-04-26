
rule Backdoor_Win64_LilithRAT_GB_MTB{
	meta:
		description = "Backdoor:Win64/LilithRAT.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 10 00 0a 00 00 "
		
	strings :
		$a_81_0 = {5c 4c 69 6c 69 74 68 2d 6d 61 73 74 65 72 5c 78 36 34 5c 44 65 62 75 67 5c 4c 69 6c 69 74 68 2e 70 64 62 } //10 \Lilith-master\x64\Debug\Lilith.pdb
		$a_80_1 = {31 32 37 2e 30 2e 30 2e 31 } //127.0.0.1  5
		$a_80_2 = {6b 65 79 6c 6f 67 2e 74 78 74 } //keylog.txt  1
		$a_80_3 = {6c 6f 67 2e 74 78 74 } //log.txt  1
		$a_80_4 = {67 65 74 61 73 79 6e 63 6b 65 79 73 74 61 74 65 } //getasynckeystate  1
		$a_80_5 = {4b 65 79 6c 6f 67 67 65 72 } //Keylogger  1
		$a_80_6 = {6b 69 6c 6c 69 6e 67 20 73 65 6c 66 } //killing self  1
		$a_80_7 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 } //powershell.exe  1
		$a_80_8 = {6b 65 79 64 75 6d 70 } //keydump  1
		$a_80_9 = {72 65 6d 6f 74 65 43 6f 6e 74 72 6f 6c } //remoteControl  1
	condition:
		((#a_81_0  & 1)*10+(#a_80_1  & 1)*5+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1) >=16
 
}