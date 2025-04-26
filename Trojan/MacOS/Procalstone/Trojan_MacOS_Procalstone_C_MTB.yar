
rule Trojan_MacOS_Procalstone_C_MTB{
	meta:
		description = "Trojan:MacOS/Procalstone.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 61 6c 69 73 74 6f 2f 75 70 6c 6f 61 64 2e 70 68 70 } //1 calisto/upload.php
		$a_00_1 = {43 33 34 4d 61 63 5f 49 6e 74 65 72 6e 65 74 5f 53 65 63 75 72 69 74 79 5f 58 39 5f 49 6e 73 74 61 6c 6c 65 72 31 31 41 70 70 44 65 6c 65 67 61 74 65 } //1 C34Mac_Internet_Security_X9_Installer11AppDelegate
		$a_00_2 = {63 61 6c 69 73 74 6f 2e 7a 69 70 } //1 calisto.zip
		$a_00_3 = {2f 2e 63 61 6c 69 73 74 6f 2f 6e 65 74 77 6f 72 6b 2e 64 61 74 } //1 /.calisto/network.dat
		$a_00_4 = {63 61 6c 69 73 74 6f 2f 6c 69 73 74 65 6e 79 65 65 2e 70 68 70 } //1 calisto/listenyee.php
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}