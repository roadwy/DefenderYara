
rule Backdoor_MacOS_Nukesped_A_MTB{
	meta:
		description = "Backdoor:MacOS/Nukesped.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {77 62 2d 62 6f 74 2e 6f 72 67 2f 63 65 72 74 70 6b 67 2e 70 68 70 } //2 wb-bot.org/certpkg.php
		$a_01_1 = {2f 76 61 72 2f 70 6b 67 6c 69 62 63 65 72 74 } //1 /var/pkglibcert
		$a_01_2 = {6e 61 6d 65 3d 22 75 70 6c 6f 61 64 22 3b 20 66 69 6c 65 6e 61 6d 65 3d 22 74 65 6d 70 2e 67 69 66 22 } //1 name="upload"; filename="temp.gif"
		$a_00_3 = {45 31 ed 89 d9 83 e1 0f 46 32 2c 21 48 63 70 04 48 39 f3 7d 2b 8b 08 83 f9 01 77 07 48 83 78 10 18 74 27 } //1
	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}