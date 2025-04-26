
rule Trojan_Win32_SuspLolbinLaunch_B_atbroker{
	meta:
		description = "Trojan:Win32/SuspLolbinLaunch.B!atbroker,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {61 00 74 00 62 00 72 00 6f 00 6b 00 65 00 72 00 20 00 } //1 atbroker 
		$a_00_1 = {2f 00 73 00 74 00 61 00 72 00 74 00 } //1 /start
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}