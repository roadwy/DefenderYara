
rule Trojan_Win32_Razy_BSA_MTB{
	meta:
		description = "Trojan:Win32/Razy.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 48 59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 68 61 73 20 62 65 65 6e 20 74 72 61 73 68 65 64 20 62 79 20 74 68 65 20 4d 45 4d 5a 20 74 72 6f 6a 61 6e 2e 20 4e 6f 77 20 65 6e 6a 6f 5f } //10 hHYour computer has been trashed by the MEMZ trojan. Now enjo_
		$a_01_1 = {4e 79 61 6e 20 43 61 74 2e 2e 2e } //1 Nyan Cat...
		$a_01_2 = {59 4f 55 52 20 43 4f 4d 50 55 54 45 52 20 48 41 53 20 42 45 45 4e 20 46 55 43 4b 45 44 20 42 59 20 54 48 45 20 4d 45 4d 5a 20 54 52 4f 4a 41 4e 2e } //1 YOUR COMPUTER HAS BEEN FUCKED BY THE MEMZ TROJAN.
		$a_01_3 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 77 6f 6e 27 74 20 62 6f 6f 74 20 75 70 20 61 67 61 69 6e 2c } //1 Your computer won't boot up again,
		$a_01_4 = {73 6f 20 75 73 65 20 69 74 20 61 73 20 6c 6f 6e 67 20 61 73 20 79 6f 75 20 63 61 6e 21 } //1 so use it as long as you can!
		$a_01_5 = {54 72 79 69 6e 67 20 74 6f 20 6b 69 6c 6c 20 4d 45 4d 5a 20 77 69 6c 6c 20 63 61 75 73 65 20 79 6f 75 72 20 73 79 73 74 65 6d 20 74 6f 20 62 65 } //1 Trying to kill MEMZ will cause your system to be
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}