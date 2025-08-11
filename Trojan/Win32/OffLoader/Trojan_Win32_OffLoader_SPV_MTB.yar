
rule Trojan_Win32_OffLoader_SPV_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.SPV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 00 6f 00 6e 00 70 00 6c 00 61 00 6e 00 65 00 2e 00 69 00 6e 00 66 00 6f 00 2f 00 66 00 6b 00 69 00 2e 00 70 00 68 00 70 00 3f 00 70 00 65 00 } //3 sonplane.info/fki.php?pe
		$a_01_1 = {73 00 65 00 61 00 62 00 75 00 73 00 69 00 6e 00 65 00 73 00 73 00 2e 00 78 00 79 00 7a 00 2f 00 66 00 6b 00 69 00 73 00 2e 00 70 00 68 00 70 00 } //3 seabusiness.xyz/fkis.php
		$a_01_2 = {2f 00 73 00 69 00 6c 00 65 00 6e 00 74 00 } //1 /silent
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1) >=7
 
}