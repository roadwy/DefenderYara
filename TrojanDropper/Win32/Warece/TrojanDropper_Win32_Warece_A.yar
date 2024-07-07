
rule TrojanDropper_Win32_Warece_A{
	meta:
		description = "TrojanDropper:Win32/Warece.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {e8 4b fc ff ff 83 c4 24 33 c0 bb 90 01 02 00 00 80 b0 90 01 02 40 00 90 01 01 40 3b c3 72 f4 8b 3d 90 01 02 40 00 56 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}