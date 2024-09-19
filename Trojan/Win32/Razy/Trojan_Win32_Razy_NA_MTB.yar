
rule Trojan_Win32_Razy_NA_MTB{
	meta:
		description = "Trojan:Win32/Razy.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 69 6e 67 20 74 6f 6b 65 6e 20 73 74 65 61 6c 69 6e 67 20 73 68 65 6c 6c 63 6f 64 65 } //1 Creating token stealing shellcode
		$a_01_1 = {45 78 70 6c 6f 69 74 69 6e 67 20 76 75 6c 6e 65 72 61 62 69 6c 69 74 79 } //1 Exploiting vulnerability
		$a_01_2 = {73 63 20 73 74 61 72 74 20 72 65 6d 6f 74 65 61 63 63 65 73 73 } //1 sc start remoteaccess
		$a_01_3 = {45 6c 65 76 61 74 69 6e 67 20 70 72 69 76 69 6c 65 67 65 73 20 74 6f 20 53 59 53 54 45 4d } //1 Elevating privileges to SYSTEM
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}