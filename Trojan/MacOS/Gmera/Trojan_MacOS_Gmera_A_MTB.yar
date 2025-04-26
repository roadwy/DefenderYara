
rule Trojan_MacOS_Gmera_A_MTB{
	meta:
		description = "Trojan:MacOS/Gmera.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6f 77 70 71 6b 73 7a 7a 2e 69 6e 66 6f 2f 6c 69 6e 6b 2e 70 68 70 } //1 owpqkszz.info/link.php
		$a_00_1 = {63 6f 6d 2e 61 70 70 49 65 2e 73 74 6f 63 6b 66 2e 73 74 6f 63 6b 73 } //1 com.appIe.stockf.stocks
		$a_00_2 = {39 53 74 6f 63 6b 66 6f 6c 69 31 31 41 70 70 44 65 6c 65 67 61 74 65 43 } //1 9Stockfoli11AppDelegateC
		$a_00_3 = {44 65 76 65 6c 6f 70 65 72 20 49 44 20 41 70 70 6c 69 63 61 74 69 6f 6e 3a 20 4e 69 6b 6f 6c 61 79 20 53 68 6d 61 74 6b 6f 20 28 35 37 4c 52 37 53 59 37 4c 46 29 } //1 Developer ID Application: Nikolay Shmatko (57LR7SY7LF)
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}