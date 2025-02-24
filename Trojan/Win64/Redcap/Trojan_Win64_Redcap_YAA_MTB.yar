
rule Trojan_Win64_Redcap_YAA_MTB{
	meta:
		description = "Trojan:Win64/Redcap.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {46 61 6b 65 20 52 54 4c 5f 42 49 54 4d 41 50 20 61 6c 6c 6f 63 61 74 65 64 20 61 74 20 61 64 64 72 65 73 73 20 3d 20 25 } //10 Fake RTL_BITMAP allocated at address = %
		$a_01_1 = {6c 65 61 6b 5f 67 61 64 67 65 74 5f 61 64 64 72 65 73 73 20 66 61 69 6c 65 64 } //1 leak_gadget_address failed
		$a_01_2 = {4b 73 4f 70 65 6e 44 65 66 61 75 6c 74 44 65 76 69 63 65 20 61 74 20 69 6e 64 65 78 20 25 64 20 66 61 69 6c 65 64 20 77 69 74 68 20 65 72 72 6f 72 20 3d 20 25 78 } //1 KsOpenDefaultDevice at index %d failed with error = %x
		$a_01_3 = {43 61 6c 6c 69 6e 67 20 57 72 69 74 65 36 34 20 77 72 61 70 70 65 72 20 74 6f 20 6f 76 65 72 77 72 69 74 65 20 63 75 72 72 65 6e 74 20 45 50 52 4f 43 45 53 53 2d 3e 54 6f 6b 65 6e } //1 Calling Write64 wrapper to overwrite current EPROCESS->Token
		$a_01_4 = {4c 65 76 65 72 61 67 69 6e 67 20 44 4b 4f 4d 20 74 6f 20 61 63 68 69 65 76 65 20 4c 50 45 } //1 Leveraging DKOM to achieve LPE
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}