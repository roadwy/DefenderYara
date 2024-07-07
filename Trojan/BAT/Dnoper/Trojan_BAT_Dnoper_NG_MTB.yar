
rule Trojan_BAT_Dnoper_NG_MTB{
	meta:
		description = "Trojan:BAT/Dnoper.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {91 03 61 1f 1a 5f 9c 59 } //10
		$a_81_1 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_81_2 = {44 65 63 72 79 70 74 } //1 Decrypt
		$a_81_3 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_81_4 = {41 6e 74 69 76 69 72 75 73 } //1 Antivirus
	condition:
		((#a_01_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=14
 
}