
rule Trojan_Win32_Staser_ER_MTB{
	meta:
		description = "Trojan:Win32/Staser.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {c1 d3 04 0f bb fb 1c 90 01 01 66 0f ba fa 90 01 01 8d 76 05 2b 5d e6 1b 4d f0 90 00 } //5
		$a_01_1 = {40 2e 76 6c 69 7a 65 72 } //1 @.vlizer
		$a_01_2 = {44 69 73 6b 49 6e 66 6f 41 } //1 DiskInfoA
		$a_01_3 = {43 72 65 61 74 65 49 4c 6f 63 6b 42 79 74 65 73 4f 6e 48 47 6c 6f 62 61 6c } //1 CreateILockBytesOnHGlobal
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}