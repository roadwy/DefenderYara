
rule Trojan_Win32_PShellDlr_HG_MTB{
	meta:
		description = "Trojan:Win32/PShellDlr.HG!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 [0-08] 20 00 90 23 80 09 30 2d 3a 61 2d 7a 25 5c 2d 2e 00 74 00 78 00 74 00 2c 00 69 00 65 00 78 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}