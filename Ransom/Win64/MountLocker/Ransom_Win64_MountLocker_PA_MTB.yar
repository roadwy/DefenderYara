
rule Ransom_Win64_MountLocker_PA_MTB{
	meta:
		description = "Ransom:Win64/MountLocker.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 00 65 00 63 00 6f 00 76 00 65 00 72 00 79 00 4d 00 61 00 6e 00 75 00 61 00 6c 00 2e 00 68 00 74 00 6d 00 6c 00 } //1 RecoveryManual.html
		$a_01_1 = {59 4f 55 52 20 4e 45 54 57 4f 52 4b 20 48 41 53 20 42 45 45 4e 20 48 41 43 4b 45 44 } //1 YOUR NETWORK HAS BEEN HACKED
		$a_01_2 = {5b 00 49 00 4e 00 46 00 4f 00 5d 00 20 00 6c 00 6f 00 63 00 6b 00 65 00 72 00 20 00 3e 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 69 00 6e 00 69 00 74 00 20 00 73 00 63 00 72 00 69 00 70 00 74 00 } //2 [INFO] locker > start init script
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=4
 
}