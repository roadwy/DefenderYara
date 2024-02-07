
rule Trojan_Win32_Szevil_A{
	meta:
		description = "Trojan:Win32/Szevil.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 52 65 67 57 72 69 74 65 20 22 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 5a 65 72 6f 45 76 69 6c 22 2c 20 72 65 73 75 6c 74 2c 20 22 52 45 47 5f 53 5a 22 } //00 00  .RegWrite "HKEY_CURRENT_USER\Software\ZeroEvil", result, "REG_SZ"
	condition:
		any of ($a_*)
 
}