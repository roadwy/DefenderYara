
rule Ransom_MSIL_Aquiyila_A{
	meta:
		description = "Ransom:MSIL/Aquiyila.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 08 00 00 "
		
	strings :
		$a_01_0 = {45 76 65 72 79 74 68 69 6e 67 20 53 65 74 21 20 56 69 72 75 73 20 66 75 6c 6c 79 20 61 63 74 69 76 61 74 65 64 } //1 Everything Set! Virus fully activated
		$a_01_1 = {73 65 65 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 65 78 70 6c 6f 64 65 21 21 21 20 4e 4f 42 4f 44 59 20 43 41 4e 20 44 45 4c 45 54 45 20 54 48 49 53 } //1 see your computer explode!!! NOBODY CAN DELETE THIS
		$a_01_2 = {43 6f 6d 70 75 74 65 72 20 64 65 73 74 72 6f 79 65 64 20 73 75 63 63 65 73 66 75 6c 6c 79 2c 20 72 65 62 6f 6f 74 69 6e 67 20 74 6f 20 66 69 6e 69 73 68 20 70 72 6f 63 65 73 73 } //1 Computer destroyed succesfully, rebooting to finish process
		$a_01_3 = {65 6e 74 65 72 20 74 68 65 20 6b 65 79 20 61 6e 64 20 72 65 2d 75 73 65 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 } //1 enter the key and re-use your computer
		$a_01_4 = {43 4f 4d 50 55 54 45 52 20 44 45 53 54 52 4f 59 45 44 2c 20 59 4f 55 20 42 45 54 54 45 52 20 50 41 59 45 44 20 54 48 45 20 46 45 45 2c 20 73 65 65 20 79 6f 75 20 6e 65 78 74 20 74 69 6d 65 } //1 COMPUTER DESTROYED, YOU BETTER PAYED THE FEE, see you next time
		$a_01_5 = {3a 2f 2f 73 61 74 6f 73 68 69 62 6f 78 2e 63 6f 6d 2f 35 35 37 38 65 34 30 37 31 32 66 62 36 64 39 66 30 32 38 62 34 35 61 31 } //2 ://satoshibox.com/5578e40712fb6d9f028b45a1
		$a_01_6 = {43 3a 5c 55 73 65 72 73 5c 4f 77 6e 65 72 5c 44 65 73 6b 74 6f 70 5c 54 4f 52 20 72 61 6e 73 6f 6d 77 61 72 65 5c 52 61 6e 73 6f 6d 77 61 72 65 20 32 2e 30 5c 6f 62 6a 5c 44 65 62 75 67 5c 54 4f 52 5f 44 45 41 4c 45 52 5f 43 55 53 54 4f 4d 31 2e 70 64 62 } //10 C:\Users\Owner\Desktop\TOR ransomware\Ransomware 2.0\obj\Debug\TOR_DEALER_CUSTOM1.pdb
		$a_01_7 = {42 61 73 73 6d 6f 6e 73 74 65 72 36 38 40 73 61 66 65 2d 6d 61 69 6c 2e 6e 65 74 } //10 Bassmonster68@safe-mail.net
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10) >=5
 
}