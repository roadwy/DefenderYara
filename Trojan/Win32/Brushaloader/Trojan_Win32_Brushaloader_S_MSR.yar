
rule Trojan_Win32_Brushaloader_S_MSR{
	meta:
		description = "Trojan:Win32/Brushaloader.S!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4e 6f 73 65 5c 42 61 73 65 5c 6c 69 73 74 65 6e 5c 74 68 69 63 6b 5c 43 6f 6d 70 61 6e 79 5c 72 69 76 65 72 5c 57 61 76 65 5c 53 61 6e 64 62 65 2e 70 64 62 } //1 Nose\Base\listen\thick\Company\river\Wave\Sandbe.pdb
		$a_01_1 = {44 65 63 6f 64 65 4f 62 6a 65 63 74 } //1 DecodeObject
		$a_01_2 = {46 69 6e 64 43 65 72 74 69 66 69 63 61 74 65 49 6e 53 74 6f 72 65 } //1 FindCertificateInStore
		$a_01_3 = {47 65 74 55 73 65 72 4f 62 6a 65 63 74 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 GetUserObjectInformation
		$a_01_4 = {47 65 74 4c 61 73 74 41 63 74 69 76 65 50 6f 70 75 70 } //1 GetLastActivePopup
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}