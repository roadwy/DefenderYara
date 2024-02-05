
rule Trojan_Win64_Rootkitdrv_B{
	meta:
		description = "Trojan:Win64/Rootkitdrv.B,SIGNATURE_TYPE_PEHSTR_EXT,ffffffc8 00 ffffffc8 00 0e 00 00 ffffffe8 03 "
		
	strings :
		$a_80_0 = {43 3a 5c 55 73 65 72 73 5c 4d 69 6b 68 61 69 6c 5c 44 65 73 6b 74 6f 70 5c 52 6f 62 6e 68 6f 6c 64 5c 78 36 34 5c 57 69 6e 37 52 65 6c 65 61 73 65 5c 52 6f 62 62 6e 68 6f 6c 64 2e 70 64 62 } //C:\Users\Mikhail\Desktop\Robnhold\x64\Win7Release\Robbnhold.pdb  64 00 
		$a_80_1 = {5c 44 65 76 69 63 65 5c 52 6f 62 6e 68 6f 6c 64 } //\Device\Robnhold  64 00 
		$a_80_2 = {5c 44 6f 73 44 65 76 69 63 65 73 5c 52 6f 62 6e 68 6f 6c 64 } //\DosDevices\Robnhold  01 00 
		$a_80_3 = {5a 77 54 65 72 6d 69 6e 61 74 65 50 72 6f 63 65 73 73 } //ZwTerminateProcess  01 00 
		$a_80_4 = {5a 77 44 65 6c 65 74 65 46 69 6c 65 } //ZwDeleteFile  01 00 
		$a_80_5 = {5a 77 53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 46 69 6c 65 } //ZwSetInformationFile  01 00 
		$a_80_6 = {5a 77 43 6c 6f 73 65 } //ZwClose  01 00 
		$a_80_7 = {5a 77 51 75 65 72 79 49 6e 66 6f 72 6d 61 74 69 6f 6e 46 69 6c 65 } //ZwQueryInformationFile  01 00 
		$a_80_8 = {5a 77 43 72 65 61 74 65 46 69 6c 65 } //ZwCreateFile  01 00 
		$a_80_9 = {49 6f 66 43 61 6c 6c 44 72 69 76 65 72 } //IofCallDriver  01 00 
		$a_80_10 = {49 6f 43 72 65 61 74 65 46 69 6c 65 53 70 65 63 69 66 79 44 65 76 69 63 65 4f 62 6a 65 63 74 48 69 6e 74 } //IoCreateFileSpecifyDeviceObjectHint  01 00 
		$a_80_11 = {4b 65 41 74 74 61 63 68 50 72 6f 63 65 73 73 } //KeAttachProcess  01 00 
		$a_80_12 = {50 73 50 72 6f 63 65 73 73 54 79 70 65 } //PsProcessType  01 00 
		$a_80_13 = {50 73 41 63 71 75 69 72 65 50 72 6f 63 65 73 73 45 78 69 74 53 79 6e 63 68 72 6f 6e 69 7a 61 74 69 6f 6e } //PsAcquireProcessExitSynchronization  00 00 
		$a_00_14 = {5d 04 00 00 de 10 04 80 5c 26 00 00 e1 10 04 80 00 00 01 00 08 00 10 00 ac 21 47 6c 75 70 74 65 62 61 2e 41 21 4d 53 52 00 00 01 40 05 82 70 00 04 00 7e 15 00 00 eb 17 e7 cd 33 4d 7c 4d a6 1d 99 41 7f 68 47 ed 00 00 00 00 62 5d 04 00 00 e1 10 04 80 5c 27 00 00 e2 10 04 80 00 00 01 00 08 00 11 00 ac 21 54 72 69 63 } //6b 62 
	condition:
		any of ($a_*)
 
}