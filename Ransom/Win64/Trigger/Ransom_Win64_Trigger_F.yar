
rule Ransom_Win64_Trigger_F{
	meta:
		description = "Ransom:Win64/Trigger.F,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 73 63 61 6e 44 69 72 } //1 main.scanDir
		$a_01_1 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 46 69 6c 65 } //1 main.encryptFile
		$a_01_2 = {6d 61 69 6e 2e 6d 61 6b 65 52 65 61 64 6d 65 46 69 6c 65 } //1 main.makeReadmeFile
		$a_01_3 = {6d 61 69 6e 2e 77 72 69 74 65 4c 6f 67 } //1 main.writeLog
		$a_01_4 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 46 69 6c 65 2e 66 75 6e 63 31 } //1 main.encryptFile.func1
		$a_01_5 = {6d 61 69 6e 2e 6d 61 6b 65 52 65 61 64 6d 65 46 69 6c 65 2e 66 75 6e 63 31 } //1 main.makeReadmeFile.func1
		$a_01_6 = {6d 61 69 6e 2e 77 72 69 74 65 4c 6f 67 2e 66 75 6e 63 31 } //1 main.writeLog.func1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}