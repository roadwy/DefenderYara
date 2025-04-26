
rule Trojan_Win32_MpTamperSrvDisableDiagTrack_A{
	meta:
		description = "Trojan:Win32/MpTamperSrvDisableDiagTrack.A,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {73 00 63 00 20 00 73 00 74 00 6f 00 70 00 20 00 [0-04] 64 00 69 00 61 00 67 00 74 00 72 00 61 00 63 00 6b 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}