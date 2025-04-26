
rule Trojan_Win32_CryptInject_RI_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {4e 75 6c 6c 73 6f 66 74 20 49 6e 73 74 61 6c 6c 20 53 79 73 74 65 6d } //1 Nullsoft Install System
		$a_03_1 = {25 25 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 [0-0f] 2c 58 79 6c 6f 6c 90 0a 3f 00 90 1b 00 2e 64 6c 6c } //5
		$a_01_2 = {43 61 6e 27 74 20 69 6e 69 74 69 61 6c 69 7a 65 20 70 6c 75 67 2d 69 6e 73 20 64 69 72 65 63 74 6f 72 79 } //1 Can't initialize plug-ins directory
		$a_01_3 = {43 6f 72 72 75 70 74 65 64 20 69 6e 73 74 61 6c 6c 65 72 3f } //1 Corrupted installer?
		$a_01_4 = {45 78 65 63 75 74 65 3a } //1 Execute:
		$a_01_5 = {24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e } //1 $$\wininit.in
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}