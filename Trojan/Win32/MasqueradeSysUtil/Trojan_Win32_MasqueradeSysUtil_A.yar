
rule Trojan_Win32_MasqueradeSysUtil_A{
	meta:
		description = "Trojan:Win32/MasqueradeSysUtil.A,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_02_0 = {3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 [0-20] 5c 00 6e 00 6f 00 74 00 65 00 70 00 61 00 64 00 2e 00 65 00 78 00 65 00 20 00 2d 00 65 00 20 00 64 00 77 00 62 00 6f 00 61 00 67 00 38 00 61 00 79 00 71 00 62 00 74 00 61 00 67 00 6b 00 61 00 } //3
	condition:
		((#a_02_0  & 1)*3) >=3
 
}