
rule Trojan_PowerShell_BatLoader_D{
	meta:
		description = "Trojan:PowerShell/BatLoader.D,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_00_0 = {2f 00 3f 00 73 00 65 00 72 00 76 00 65 00 72 00 6e 00 61 00 6d 00 65 00 3d 00 6d 00 73 00 69 00 } //10 /?servername=msi
	condition:
		((#a_00_0  & 1)*10) >=10
 
}