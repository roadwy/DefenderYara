
rule DoS_Win32_SDeleteAbuse_C_dha{
	meta:
		description = "DoS:Win32/SDeleteAbuse.C!dha,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {73 00 64 00 65 00 6c 00 65 00 74 00 65 00 2e 00 65 00 78 00 65 00 20 00 2d 00 61 00 63 00 63 00 65 00 70 00 74 00 65 00 75 00 6c 00 61 00 20 00 2d 00 72 00 20 00 2d 00 73 00 20 00 2d 00 71 00 20 00 ?? ?? 3a 00 [0-04] 2a 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}