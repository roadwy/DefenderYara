
rule Trojan_Win32_SusipicousMshatCMD_S02{
	meta:
		description = "Trojan:Win32/SusipicousMshatCMD.S02,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 68 00 74 00 61 00 } //1 mshta
		$a_00_1 = {2e 00 68 00 74 00 61 00 } //-10 .hta
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*-10) >=1
 
}