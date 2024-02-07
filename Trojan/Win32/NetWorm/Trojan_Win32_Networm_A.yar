
rule Trojan_Win32_Networm_A{
	meta:
		description = "Trojan:Win32/Networm.A,SIGNATURE_TYPE_CMDHSTR_EXT,64 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_00_0 = {2f 00 63 00 20 00 6e 00 65 00 74 00 20 00 73 00 65 00 73 00 73 00 69 00 6f 00 6e 00 20 00 2f 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 2f 00 79 00 20 00 3e 00 20 00 6e 00 75 00 6c 00 } //00 00  /c net session /delete /y > nul
	condition:
		any of ($a_*)
 
}