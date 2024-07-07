
rule Trojan_Win32_Vundo_IP{
	meta:
		description = "Trojan:Win32/Vundo.IP,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_13_0 = {64 6c 6c 00 61 00 62 00 00 00 00 90 09 51 00 49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 00 90 00 00 } //1
	condition:
		((#a_13_0  & 1)*1) >=1
 
}