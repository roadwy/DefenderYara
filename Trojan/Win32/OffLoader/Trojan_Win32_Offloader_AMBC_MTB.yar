
rule Trojan_Win32_Offloader_AMBC_MTB{
	meta:
		description = "Trojan:Win32/Offloader.AMBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_80_0 = {3a 2f 2f 73 68 6f 70 62 65 61 64 2e 6f 6e 6c 69 6e 65 2f 62 61 72 74 2e 70 68 70 } //://shopbead.online/bart.php  2
		$a_80_1 = {3a 2f 2f 73 6d 65 6c 6c 63 69 72 63 6c 65 2e 73 69 74 65 2f 74 72 61 63 6b 65 72 2f 74 68 61 6e 6b 5f 79 6f 75 2e 70 68 70 } //://smellcircle.site/tracker/thank_you.php  2
		$a_80_2 = {2f 73 69 6c 65 6e 74 } ///silent  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1) >=5
 
}
rule Trojan_Win32_Offloader_AMBC_MTB_2{
	meta:
		description = "Trojan:Win32/Offloader.AMBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 63 00 6c 00 61 00 6d 00 77 00 69 00 72 00 65 00 2e 00 78 00 79 00 7a 00 2f 00 63 00 68 00 2e 00 70 00 68 00 70 00 } //2 http://clamwire.xyz/ch.php
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 72 00 65 00 63 00 65 00 73 00 73 00 6f 00 72 00 61 00 6e 00 67 00 65 00 2e 00 78 00 79 00 7a 00 2f 00 63 00 68 00 2e 00 70 00 68 00 70 00 } //2 http://recessorange.xyz/ch.php
		$a_01_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65 } //1
		$a_01_3 = {72 00 65 00 73 00 74 00 61 00 72 00 74 00 20 00 74 00 68 00 65 00 20 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 6e 00 6f 00 77 00 } //1 restart the computer now
		$a_01_4 = {59 00 65 00 73 00 2c 00 20 00 49 00 20 00 77 00 6f 00 75 00 6c 00 64 00 20 00 6c 00 69 00 6b 00 65 00 20 00 74 00 6f 00 20 00 76 00 69 00 65 00 77 00 20 00 74 00 68 00 65 00 20 00 52 00 45 00 41 00 44 00 4d 00 45 00 20 00 66 00 69 00 6c 00 65 00 } //1 Yes, I would like to view the README file
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}