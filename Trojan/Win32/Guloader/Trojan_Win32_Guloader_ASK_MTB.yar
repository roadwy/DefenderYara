
rule Trojan_Win32_Guloader_ASK_MTB{
	meta:
		description = "Trojan:Win32/Guloader.ASK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {45 79 65 6c 65 73 73 6e 65 73 73 5c 63 61 72 6f 75 73 61 6c 73 5c 6b 61 6d 6d 65 72 6a 75 6e 6b 65 72 6e 65 73 } //1 Eyelessness\carousals\kammerjunkernes
		$a_01_1 = {75 70 62 75 6f 79 5c 53 65 69 67 6e 69 6f 72 61 67 65 2e 68 74 6d } //1 upbuoy\Seigniorage.htm
		$a_01_2 = {62 6c 6f 6b 74 69 6c 62 61 67 65 6b 6f 62 6c 69 6e 67 73 63 68 69 70 5c 6d 61 74 68 65 6d 61 74 69 63 69 7a 65 } //1 bloktilbagekoblingschip\mathematicize
		$a_01_3 = {42 61 64 65 76 72 65 6c 73 65 72 73 2e 69 6d 70 } //1 Badevrelsers.imp
		$a_01_4 = {73 6b 6e 64 73 65 6c 73 67 65 72 6e 69 6e 67 65 72 6e 65 73 2e 74 78 74 } //1 skndselsgerningernes.txt
		$a_01_5 = {64 75 6c 63 69 66 69 63 61 74 69 6f 6e 2e 69 6e 69 } //1 dulcification.ini
		$a_01_6 = {76 69 64 65 6f 62 61 61 6e 64 6f 70 74 61 67 65 72 65 6e 2e 73 65 6e } //1 videobaandoptageren.sen
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}