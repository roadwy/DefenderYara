
rule Trojan_PowerShell_DownInfo_C{
	meta:
		description = "Trojan:PowerShell/DownInfo.C,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {24 00 70 00 73 00 68 00 6f 00 6d 00 65 00 5b 00 [0-04] 5d 00 2b 00 24 00 70 00 73 00 68 00 6f 00 6d 00 65 00 5b 00 [0-04] 5d 00 2b 00 27 00 78 00 27 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}