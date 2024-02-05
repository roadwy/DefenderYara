
rule TrojanProxy_Win32_Thunker_F{
	meta:
		description = "TrojanProxy:Win32/Thunker.F,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {7f 0d ff 44 24 10 83 7c 24 10 05 7c 90 01 01 eb 08 c7 44 24 18 01 00 00 00 68 90 01 02 00 10 68 90 01 01 31 00 10 90 09 0d 00 ff 90 01 01 55 e8 90 01 01 90 03 01 01 02 03 00 00 83 c4 34 85 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}