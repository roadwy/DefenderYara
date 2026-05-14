
rule Ransom_MSIL_LockScreen_AYA_MTB{
	meta:
		description = "Ransom:MSIL/LockScreen.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 61 6e 73 6f 6d 77 61 72 65 6c 75 63 6b 79 73 74 61 61 74 72 6f 73 2e 70 64 62 } //5 Ransomwareluckystaatros.pdb
		$a_01_1 = {52 61 6e 73 6f 6d 77 61 72 65 6c 75 63 6b 79 73 74 61 61 74 72 6f 73 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //2 Ransomwareluckystaatros.Form1.resources
		$a_00_2 = {73 00 65 00 6e 00 74 00 20 00 6d 00 65 00 20 00 32 00 30 00 30 00 24 00 20 00 74 00 6f 00 20 00 74 00 68 00 69 00 73 00 20 00 61 00 64 00 64 00 72 00 65 00 73 00 73 00 20 00 74 00 6f 00 20 00 72 00 65 00 63 00 6f 00 76 00 65 00 72 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 } //2 sent me 200$ to this address to recover your files
		$a_01_3 = {24 36 62 39 33 64 31 33 34 2d 32 36 32 37 2d 34 30 64 34 2d 61 38 35 63 2d 65 62 37 66 63 38 61 33 63 66 37 35 } //1 $6b93d134-2627-40d4-a85c-eb7fc8a3cf75
		$a_01_4 = {49 73 52 75 6e 6e 69 6e 67 41 73 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 } //1 IsRunningAsAdministrator
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_00_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=11
 
}