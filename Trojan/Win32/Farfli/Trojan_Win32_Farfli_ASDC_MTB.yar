
rule Trojan_Win32_Farfli_ASDC_MTB{
	meta:
		description = "Trojan:Win32/Farfli.ASDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 02 56 ff 15 [0-04] c7 45 bc 53 59 53 54 c7 45 c0 45 4d 5c 43 c7 45 c4 75 72 72 65 c7 45 c8 6e 74 43 6f c7 45 cc 6e 74 72 6f c7 45 d0 6c 53 65 74 c7 45 d4 5c 53 65 72 c7 45 d8 76 69 63 65 c7 45 dc 73 5c 25 73 } //1
		$a_01_1 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 73 63 76 68 6f 73 74 2e 65 78 65 } //1 C:\Program Files\Common Files\scvhost.exe
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}