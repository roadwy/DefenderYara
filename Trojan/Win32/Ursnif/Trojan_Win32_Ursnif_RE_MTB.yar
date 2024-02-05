
rule Trojan_Win32_Ursnif_RE_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 c1 05 2b 0d 90 01 04 89 0d 90 01 04 68 90 01 04 8b 90 01 05 52 e8 90 01 04 83 90 01 02 03 90 01 05 a3 90 01 04 0f 90 01 06 89 90 01 02 83 90 00 } //01 00 
		$a_02_1 = {83 e9 2c 0f 90 01 06 2b 90 01 01 a1 90 01 04 2b 90 01 01 a3 90 01 04 8b 90 01 05 83 90 01 02 2b 90 01 05 89 90 01 05 0f 90 01 06 0f 90 01 06 2b 90 01 01 81 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}