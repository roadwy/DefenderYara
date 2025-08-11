
rule Trojan_Win32_SchExec_HJ_MTB{
	meta:
		description = "Trojan:Win32/SchExec.HJ!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,10 00 10 00 03 00 00 "
		
	strings :
		$a_00_0 = {2f 00 63 00 72 00 65 00 61 00 74 00 65 00 } //1 /create
		$a_00_1 = {20 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 20 00 } //5  svchost 
		$a_00_2 = {2f 00 74 00 72 00 20 00 63 00 3a 00 5c 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 64 00 61 00 74 00 61 00 } //10 /tr c:\programdata
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*5+(#a_00_2  & 1)*10) >=16
 
}