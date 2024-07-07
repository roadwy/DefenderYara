
rule Trojan_BAT_Zusy_AMBC_MTB{
	meta:
		description = "Trojan:BAT/Zusy.AMBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {53 76 64 72 64 2e 65 78 65 } //Svdrd.exe  1
		$a_80_1 = {53 76 64 72 64 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //Svdrd.Resources.resources  1
		$a_80_2 = {41 65 73 4d 61 6e 61 67 65 64 } //AesManaged  1
		$a_80_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //CreateDecryptor  1
		$a_80_4 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //DownloadString  1
		$a_80_5 = {62 6d 56 33 59 6e 52 79 4c 6d 56 34 5a 51 3d 3d } //bmV3YnRyLmV4ZQ==  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}