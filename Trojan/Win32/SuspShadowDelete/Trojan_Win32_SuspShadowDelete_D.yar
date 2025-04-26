
rule Trojan_Win32_SuspShadowDelete_D{
	meta:
		description = "Trojan:Win32/SuspShadowDelete.D,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_00_0 = {77 00 62 00 61 00 64 00 6d 00 69 00 6e 00 90 00 02 00 30 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 63 00 61 00 74 00 61 00 6c 00 6f 00 67 00 } //2
	condition:
		((#a_00_0  & 1)*2) >=2
 
}