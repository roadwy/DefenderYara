
rule Trojan_PowerShell_DownInfo_A{
	meta:
		description = "Trojan:PowerShell/DownInfo.A,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_00_0 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 77 00 65 00 62 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 20 00 2d 00 75 00 72 00 69 00 20 00 22 00 24 00 61 00 70 00 69 00 2f 00 73 00 63 00 72 00 69 00 70 00 74 00 3f 00 6d 00 61 00 63 00 68 00 69 00 6e 00 65 00 69 00 64 00 3d 00 24 00 67 00 75 00 69 00 64 00 22 00 } //10 invoke-webrequest -uri "$api/script?machineid=$guid"
	condition:
		((#a_00_0  & 1)*10) >=10
 
}