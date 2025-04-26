
rule Ransom_MSIL_Cryptolocker_AYA_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 61 79 6c 6f 61 64 2e 4c 6f 63 6b 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //2 Payload.LockForm.resources
		$a_01_1 = {43 72 79 70 74 6f 20 4c 6f 63 6b 65 72 5c 50 61 79 6c 6f 61 64 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 50 61 79 6c 6f 61 64 2e 70 64 62 } //1 Crypto Locker\Payload\obj\Release\Payload.pdb
		$a_01_2 = {4b 69 6c 6c 41 6c 6c 50 72 6f 63 65 73 73 65 73 } //1 KillAllProcesses
		$a_01_3 = {24 36 34 34 66 63 35 33 65 2d 31 34 62 39 2d 34 64 61 64 2d 39 30 39 37 2d 37 33 36 33 37 63 34 66 37 62 34 64 } //1 $644fc53e-14b9-4dad-9097-73637c4f7b4d
		$a_00_4 = {52 00 65 00 6d 00 6f 00 76 00 65 00 46 00 72 00 6f 00 6d 00 53 00 74 00 61 00 72 00 74 00 75 00 70 00 2e 00 62 00 61 00 74 00 } //1 RemoveFromStartup.bat
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=6
 
}