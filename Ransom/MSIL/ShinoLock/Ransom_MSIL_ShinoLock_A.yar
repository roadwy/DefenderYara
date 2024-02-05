
rule Ransom_MSIL_ShinoLock_A{
	meta:
		description = "Ransom:MSIL/ShinoLock.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 01 00 "
		
	strings :
		$a_80_0 = {53 68 69 6e 6f 4c 6f 63 6b 65 72 00 } //ShinoLocker  01 00 
		$a_80_1 = {53 68 69 6e 6f 4c 6f 63 6b 65 72 4d 61 69 6e 2e 65 78 65 00 } //ShinoLockerMain.exe  01 00 
		$a_80_2 = {53 68 69 6e 6f 4c 6f 63 6b 65 72 20 53 65 72 76 65 72 } //ShinoLocker Server  01 00 
		$a_80_3 = {44 65 63 72 79 70 74 20 46 69 6c 65 73 20 26 26 20 55 6e 69 6e 73 74 61 6c 6c 20 4d 65 } //Decrypt Files && Uninstall Me  01 00 
		$a_80_4 = {2e 73 68 69 6e 6f } //.shino  01 00 
		$a_80_5 = {4b 65 79 20 69 73 20 77 72 6f 6e 67 21 } //Key is wrong!  01 00 
		$a_80_6 = {53 68 69 6e 6f 4c 6f 63 6b 65 72 45 6e 63 72 79 70 74 65 64 46 69 6c 65 } //ShinoLockerEncryptedFile  01 00 
		$a_80_7 = {53 68 69 6e 6f 4c 6f 63 6b 65 72 4d 61 69 6e 2e 4d 79 00 } //ShinoLockerMain.My  00 00 
		$a_00_8 = {5d 04 00 } //00 67 
	condition:
		any of ($a_*)
 
}