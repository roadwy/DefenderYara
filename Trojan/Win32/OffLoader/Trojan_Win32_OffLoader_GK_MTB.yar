
rule Trojan_Win32_OffLoader_GK_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.GK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {53 6f 66 74 77 61 72 65 5c 41 6d 62 61 53 6f 66 74 47 6d 62 48 } //1 Software\AmbaSoftGmbH
		$a_81_1 = {53 6f 66 74 77 61 72 65 5c 53 50 6f 6c 6f 43 6c 65 61 6e 65 72 } //1 Software\SPoloCleaner
		$a_81_2 = {53 6f 66 74 77 61 72 65 5c 73 64 66 77 73 64 66 73 36 64 66 } //1 Software\sdfwsdfs6df
		$a_81_3 = {64 3d 6e 73 69 73 26 6d 73 67 3d 26 72 3d 6f 66 66 65 72 5f 65 78 65 63 75 74 69 6f 6e 26 72 6b 3d 6e 6f } //1 d=nsis&msg=&r=offer_execution&rk=no
		$a_81_4 = {73 65 74 5f 30 2e 65 78 65 } //1 set_0.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}