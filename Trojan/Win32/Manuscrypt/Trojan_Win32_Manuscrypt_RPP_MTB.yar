
rule Trojan_Win32_Manuscrypt_RPP_MTB{
	meta:
		description = "Trojan:Win32/Manuscrypt.RPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 44 24 04 3c 00 00 00 c7 44 24 08 40 04 00 00 c7 44 24 18 ?? ?? ?? ?? c7 44 24 20 01 00 00 00 89 74 24 14 66 c7 44 24 40 72 00 66 c7 44 24 42 75 00 66 c7 44 24 44 6e 00 66 c7 44 24 46 61 00 66 c7 44 24 48 73 00 66 c7 44 24 4a 00 00 ff d1 } //1
		$a_01_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 45 78 } //1 ShellExecuteEx
		$a_01_2 = {43 72 65 61 74 65 44 69 61 6c 6f 67 49 6e 64 69 72 65 63 74 50 61 72 61 6d } //1 CreateDialogIndirectParam
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}