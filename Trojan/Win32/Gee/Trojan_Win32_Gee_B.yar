
rule Trojan_Win32_Gee_B{
	meta:
		description = "Trojan:Win32/Gee.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {49 45 48 6f 73 74 32 53 65 72 76 69 63 65 73 90 03 0c 11 00 ff ff ff ff 7d 18 40 00 91 18 40 00 49 45 48 6f 73 74 32 20 53 65 72 76 69 63 65 73 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}