
rule Trojan_Win64_CryptInject_RHAQ_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.RHAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_00_0 = {50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 44 00 72 00 69 00 76 00 65 00 } //2 PhysicalDrive
		$a_01_1 = {2f 2f 69 6e 64 69 65 66 69 72 65 2e 69 6f 3a 33 33 30 36 2f 74 69 6d 65 74 72 61 63 6b } //3 //indiefire.io:3306/timetrack
		$a_01_2 = {5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 45 78 6f 64 75 73 5c 65 78 6f 64 75 73 2e 77 61 6c 6c 65 74 5c } //1 \AppData\Roaming\Exodus\exodus.wallet\
		$a_01_3 = {5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 } //1 \AppData\Local\Google\Chrome\User Data
		$a_01_4 = {2f 6d 65 64 69 61 2f 69 74 65 6d 6d 65 64 69 61 } //1 /media/itemmedia
		$a_03_5 = {50 45 00 00 64 86 06 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 0e 29 00 56 00 00 00 02 03 00 00 00 00 00 ac 51 } //2
	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*2) >=10
 
}