
rule Ransom_MSIL_HiddenTear_A{
	meta:
		description = "Ransom:MSIL/HiddenTear.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 52 00 45 00 41 00 44 00 4d 00 45 00 2e 00 74 00 78 00 74 00 } //01 00 
		$a_01_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 76 00 69 00 72 00 6f 00 2e 00 6d 00 6c 00 65 00 79 00 64 00 69 00 65 00 72 00 2e 00 66 00 72 00 2f 00 6e 00 6f 00 61 00 75 00 74 00 68 00 } //01 00 
		$a_01_2 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 13 2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 00 03 5f 00 00 01 00 23 4b 00 65 00 79 00 4c 00 6f 00 67 00 67 00 65 00 72 00 20 00 53 00 74 00 61 00 72 00 74 00 65 00 64 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_HiddenTear_A_2{
	meta:
		description = "Ransom:MSIL/HiddenTear.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 18 00 00 02 00 "
		
	strings :
		$a_80_0 = {23 48 6f 77 5f 44 65 63 72 79 70 74 5f 46 69 6c 65 73 2e 74 78 74 } //#How_Decrypt_Files.txt  02 00 
		$a_80_1 = {5c 44 65 73 6b 74 6f 70 5c 74 65 73 74 5c 52 45 41 44 5f 49 54 2e 74 78 74 } //\Desktop\test\READ_IT.txt  02 00 
		$a_80_2 = {5c 44 65 73 6b 74 6f 70 5c 48 61 63 6b 65 64 2e 74 78 74 } //\Desktop\Hacked.txt  02 00 
		$a_80_3 = {49 6e 66 69 6e 69 74 65 44 65 63 72 79 70 74 6f 72 40 50 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //InfiniteDecryptor@Protonmail.com  02 00 
		$a_80_4 = {31 43 43 6e 46 68 62 4c 54 31 56 53 4d 55 71 58 61 53 71 73 59 55 41 77 63 47 55 34 65 76 6b 62 4a 6f } //1CCnFhbLT1VSMUqXaSqsYUAwcGU4evkbJo  02 00 
		$a_80_5 = {62 6c 61 63 6b 67 6f 6c 64 31 32 33 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //blackgold123@protonmail.com  02 00 
		$a_80_6 = {76 6e 72 61 6e 73 6f 6d 77 61 72 65 40 7a 6f 68 6f 2e 63 6f 6d } //vnransomware@zoho.com  02 00 
		$a_80_7 = {49 6e 66 69 6e 69 74 65 54 65 61 72 } //InfiniteTear  02 00 
		$a_80_8 = {68 69 64 64 65 6e 5f 74 65 61 72 } //hidden_tear  02 00 
		$a_80_9 = {68 69 64 64 65 6e 2d 74 65 61 72 } //hidden-tear  02 00 
		$a_80_10 = {68 69 64 64 65 6e 20 74 65 61 72 } //hidden tear  02 00 
		$a_80_11 = {49 6e 66 69 6e 69 74 65 49 6e 63 20 32 30 31 37 } //InfiniteInc 2017  02 00 
		$a_80_12 = {52 61 6e 73 6f 6d 77 61 72 65 20 55 6c 74 69 6d 6f } //Ransomware Ultimo  02 00 
		$a_80_13 = {22 49 6e 66 69 6e 69 74 65 54 65 61 72 20 52 61 6e 73 6f 6d 77 61 72 65 22 } //"InfiniteTear Ransomware"  02 00 
		$a_80_14 = {22 49 6e 66 69 6e 69 74 65 20 44 65 63 72 79 70 74 6f 72 22 } //"Infinite Decryptor"  02 00 
		$a_80_15 = {22 49 6e 66 69 6e 69 74 65 20 52 61 6e 73 6f 6d 77 61 72 65 22 } //"Infinite Ransomware"  02 00 
		$a_80_16 = {2e 49 6e 66 69 6e 69 74 65 } //.Infinite  02 00 
		$a_80_17 = {2e 6c 6f 63 6b 65 64 } //.locked  02 00 
		$a_80_18 = {41 6c 6c 20 79 6f 75 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 2c 20 73 75 63 68 20 61 73 20 64 6f 63 75 6d 65 6e 74 73 2c 20 69 6d 61 67 65 73 2c 20 76 69 64 65 6f 73 2c 20 64 61 74 61 62 61 73 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //All your important files, such as documents, images, videos, databases are encrypted  02 00 
		$a_80_19 = {4f 6f 6f 6f 70 70 70 73 73 73 20 59 6f 75 72 20 46 69 6c 65 73 20 48 61 73 20 42 65 65 6e 20 45 6e 63 72 79 70 74 65 64 } //Oooopppsss Your Files Has Been Encrypted  01 00 
		$a_80_20 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 51 75 69 65 74 } //vssadmin.exe delete shadows /all /Quiet  01 00 
		$a_80_21 = {57 4d 49 43 2e 65 78 65 20 73 68 61 64 6f 77 63 6f 70 79 20 64 65 6c 65 74 65 } //WMIC.exe shadowcopy delete  01 00 
		$a_80_22 = {42 63 64 65 64 69 74 2e 65 78 65 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 6e 6f } //Bcdedit.exe /set {default} recoveryenabled no  01 00 
		$a_80_23 = {42 63 64 65 64 69 74 2e 65 78 65 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 62 6f 6f 74 73 74 61 74 75 73 70 6f 6c 69 63 79 20 69 67 6e 6f 72 65 61 6c 6c 66 61 69 6c 75 72 65 73 } //Bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures  00 00 
		$a_00_24 = {5d 04 00 00 8f a7 03 80 } //5c 2d 
	condition:
		any of ($a_*)
 
}