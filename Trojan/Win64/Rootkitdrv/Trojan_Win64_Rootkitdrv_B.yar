
rule Trojan_Win64_Rootkitdrv_B{
	meta:
		description = "Trojan:Win64/Rootkitdrv.B,SIGNATURE_TYPE_PEHSTR_EXT,ffffffc8 00 ffffffc8 00 0e 00 00 "
		
	strings :
		$a_80_0 = {43 3a 5c 55 73 65 72 73 5c 4d 69 6b 68 61 69 6c 5c 44 65 73 6b 74 6f 70 5c 52 6f 62 6e 68 6f 6c 64 5c 78 36 34 5c 57 69 6e 37 52 65 6c 65 61 73 65 5c 52 6f 62 62 6e 68 6f 6c 64 2e 70 64 62 } //C:\Users\Mikhail\Desktop\Robnhold\x64\Win7Release\Robbnhold.pdb  1000
		$a_80_1 = {5c 44 65 76 69 63 65 5c 52 6f 62 6e 68 6f 6c 64 } //\Device\Robnhold  100
		$a_80_2 = {5c 44 6f 73 44 65 76 69 63 65 73 5c 52 6f 62 6e 68 6f 6c 64 } //\DosDevices\Robnhold  100
		$a_80_3 = {5a 77 54 65 72 6d 69 6e 61 74 65 50 72 6f 63 65 73 73 } //ZwTerminateProcess  1
		$a_80_4 = {5a 77 44 65 6c 65 74 65 46 69 6c 65 } //ZwDeleteFile  1
		$a_80_5 = {5a 77 53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 46 69 6c 65 } //ZwSetInformationFile  1
		$a_80_6 = {5a 77 43 6c 6f 73 65 } //ZwClose  1
		$a_80_7 = {5a 77 51 75 65 72 79 49 6e 66 6f 72 6d 61 74 69 6f 6e 46 69 6c 65 } //ZwQueryInformationFile  1
		$a_80_8 = {5a 77 43 72 65 61 74 65 46 69 6c 65 } //ZwCreateFile  1
		$a_80_9 = {49 6f 66 43 61 6c 6c 44 72 69 76 65 72 } //IofCallDriver  1
		$a_80_10 = {49 6f 43 72 65 61 74 65 46 69 6c 65 53 70 65 63 69 66 79 44 65 76 69 63 65 4f 62 6a 65 63 74 48 69 6e 74 } //IoCreateFileSpecifyDeviceObjectHint  1
		$a_80_11 = {4b 65 41 74 74 61 63 68 50 72 6f 63 65 73 73 } //KeAttachProcess  1
		$a_80_12 = {50 73 50 72 6f 63 65 73 73 54 79 70 65 } //PsProcessType  1
		$a_80_13 = {50 73 41 63 71 75 69 72 65 50 72 6f 63 65 73 73 45 78 69 74 53 79 6e 63 68 72 6f 6e 69 7a 61 74 69 6f 6e } //PsAcquireProcessExitSynchronization  1
	condition:
		((#a_80_0  & 1)*1000+(#a_80_1  & 1)*100+(#a_80_2  & 1)*100+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*1) >=200
 
}