
rule Trojan_Win64_DllHijack_CCJU_MTB{
	meta:
		description = "Trojan:Win64/DllHijack.CCJU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 42 61 63 6b 64 6f 6f 72 } //2 CreateBackdoor
		$a_01_1 = {51 75 65 72 79 44 65 76 69 63 65 49 6e 66 6f 72 6d 61 74 69 6f 6e } //2 QueryDeviceInformation
		$a_01_2 = {62 69 6e 64 53 68 65 6c 6c } //1 bindShell
		$a_01_3 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 20 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 63 00 6f 00 72 00 65 00 64 00 65 00 76 00 69 00 63 00 65 00 69 00 6e 00 66 00 6f 00 2e 00 64 00 6c 00 6c 00 2c 00 43 00 72 00 65 00 61 00 74 00 65 00 42 00 61 00 63 00 6b 00 64 00 6f 00 6f 00 72 00 } //1 rundll32 windowscoredeviceinfo.dll,CreateBackdoor
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}