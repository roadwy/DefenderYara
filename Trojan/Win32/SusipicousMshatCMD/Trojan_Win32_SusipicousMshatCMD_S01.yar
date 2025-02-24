
rule Trojan_Win32_SusipicousMshatCMD_S01{
	meta:
		description = "Trojan:Win32/SusipicousMshatCMD.S01,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 68 00 74 00 61 00 } //1 mshta
		$a_02_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-40] 2e 00 68 00 74 00 61 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}