
rule Ransom_MSIL_Lossymem{
	meta:
		description = "Ransom:MSIL/Lossymem,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {4c 6f 6e 67 54 65 72 6d 4d 65 6d 6f 72 79 4c 6f 73 73 2e 65 78 65 } //2 LongTermMemoryLoss.exe
		$a_01_1 = {43 3a 5c 55 73 65 72 73 5c 41 73 6d 63 78 31 35 5c 64 6f 63 75 6d 65 6e 74 73 5c 76 69 73 75 61 6c 20 73 74 75 64 69 6f 20 32 30 31 37 5c 50 72 6f 6a 65 63 74 73 5c 4c 6f 6e 67 54 65 72 6d 4d 65 6d 6f 72 79 4c 6f 73 73 5c 4c 6f 6e 67 54 65 72 6d 4d 65 6d 6f 72 79 4c 6f 73 73 5c 6f 62 6a 5c 44 65 62 75 67 5c 4c 6f 6e 67 54 65 72 6d 4d 65 6d 6f 72 79 4c 6f 73 73 2e 70 64 62 } //2 C:\Users\Asmcx15\documents\visual studio 2017\Projects\LongTermMemoryLoss\LongTermMemoryLoss\obj\Debug\LongTermMemoryLoss.pdb
		$a_01_2 = {4c 6f 6e 67 54 65 72 6d 4d 65 6d 6f 72 79 4c 6f 73 73 2e 57 61 72 6e 47 55 49 2e 72 65 73 6f 75 72 63 65 73 } //2 LongTermMemoryLoss.WarnGUI.resources
		$a_01_3 = {4c 00 6f 00 6e 00 67 00 54 00 65 00 72 00 6d 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 4c 00 6f 00 73 00 73 00 } //2 LongTermMemoryLoss
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=6
 
}