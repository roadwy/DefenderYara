
rule Trojan_Win32_ClickFix_DAR_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DAR!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,65 00 65 00 03 00 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 68 00 74 00 61 00 } //100 mshta
		$a_00_1 = {43 00 49 00 6f 00 75 00 64 00 66 00 49 00 61 00 72 00 65 00 20 00 55 00 6e 00 69 00 71 00 75 00 65 00 20 00 4f 00 6e 00 65 00 2d 00 74 00 69 00 6d 00 65 00 } //1 CIoudfIare Unique One-time
		$a_00_2 = {55 00 73 00 65 00 72 00 20 00 52 00 65 00 66 00 3a 00 20 00 41 00 6c 00 70 00 68 00 61 00 } //1 User Ref: Alpha
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=101
 
}