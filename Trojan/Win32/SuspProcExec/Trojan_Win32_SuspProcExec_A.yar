
rule Trojan_Win32_SuspProcExec_A{
	meta:
		description = "Trojan:Win32/SuspProcExec.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_80_0 = {5c 54 65 6d 70 5c 61 74 74 61 63 6b 69 71 5f 6d 61 73 71 75 65 72 61 64 69 6e 67 5c } //\Temp\attackiq_masquerading\  1
	condition:
		((#a_80_0  & 1)*1) >=1
 
}