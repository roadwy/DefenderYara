
rule Trojan_Win32_PSObfus_BSA_MTB{
	meta:
		description = "Trojan:Win32/PSObfus.BSA!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 20 00 24 00 } //1 powershell $
		$a_00_1 = {2e 00 72 00 65 00 70 00 6c 00 61 00 63 00 65 00 28 00 } //1 .replace(
		$a_00_2 = {2b 00 20 00 5b 00 63 00 68 00 61 00 72 00 5d 00 } //1 + [char]
		$a_00_3 = {5b 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 43 00 6f 00 6e 00 76 00 65 00 72 00 74 00 5d 00 3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 20 00 24 00 } //1 [System.Convert]::FromBase64String( $
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}