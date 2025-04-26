
rule Trojan_PowerShell_Phifuse_B{
	meta:
		description = "Trojan:PowerShell/Phifuse.B,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {22 00 49 00 45 00 58 00 20 00 28 00 5b 00 54 00 65 00 78 00 74 00 2e 00 45 00 6e 00 63 00 6f 00 64 00 69 00 6e 00 67 00 5d 00 3a 00 3a 00 55 00 4e 00 49 00 43 00 4f 00 44 00 45 00 2e 00 47 00 65 00 74 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 5b 00 43 00 6f 00 6e 00 76 00 65 00 72 00 74 00 5d 00 3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 28 00 67 00 70 00 20 00 48 00 4b 00 43 00 55 00 3a 00 5c 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 } //1 "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:\\Software
	condition:
		((#a_00_0  & 1)*1) >=1
 
}