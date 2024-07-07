
rule Ransom_Win32_DMALocker_A{
	meta:
		description = "Ransom:Win32/DMALocker.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {44 4d 41 20 4c 6f 63 6b 65 72 } //1 DMA Locker
		$a_01_1 = {4f 74 77 69 65 72 61 6e 69 65 20 70 6c 69 6b 75 3a } //1 Otwieranie pliku:
		$a_01_2 = {63 72 79 70 74 65 64 69 6e 66 6f } //1 cryptedinfo
		$a_01_3 = {73 2d 61 64 76 69 63 65 2d 6f 6e 2d 63 72 79 70 74 6f 6c 6f 63 6b 65 72 2d 6a 75 73 74 2d 70 61 } //1 s-advice-on-cryptolocker-just-pa
		$a_01_4 = {44 4d 41 4c 4f 43 4b } //1 DMALOCK
		$a_00_5 = {49 46 20 46 49 4c 45 53 20 55 4e 4c 4f 43 4b 49 4e 47 20 50 52 4f 43 45 44 55 52 45 20 49 53 20 41 4c 52 45 41 44 59 20 57 4f 52 4b 49 4e 47 2c } //1 IF FILES UNLOCKING PROCEDURE IS ALREADY WORKING,
		$a_00_6 = {48 4f 57 20 54 4f 20 50 41 59 20 55 53 20 41 4e 44 20 55 4e 4c 4f 43 4b 20 59 4f 55 52 20 46 49 4c 45 53 3f } //1 HOW TO PAY US AND UNLOCK YOUR FILES?
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=5
 
}