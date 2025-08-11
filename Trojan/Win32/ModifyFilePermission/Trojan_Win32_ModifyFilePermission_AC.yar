
rule Trojan_Win32_ModifyFilePermission_AC{
	meta:
		description = "Trojan:Win32/ModifyFilePermission.AC,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_02_0 = {69 00 63 00 61 00 63 00 6c 00 73 00 [0-0a] 3a 00 5c 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 66 00 69 00 6c 00 65 00 73 00 5c 00 61 00 74 00 74 00 61 00 63 00 6b 00 69 00 71 00 5f 00 70 00 65 00 72 00 6d 00 69 00 73 00 73 00 69 00 6f 00 6e 00 73 00 5f 00 74 00 65 00 73 00 74 00 [0-08] 67 00 72 00 61 00 6e 00 74 00 20 00 75 00 73 00 65 00 72 00 73 00 3a 00 6d 00 } //3
	condition:
		((#a_02_0  & 1)*3) >=3
 
}