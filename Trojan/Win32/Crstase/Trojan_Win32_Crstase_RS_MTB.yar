
rule Trojan_Win32_Crstase_RS_MTB{
	meta:
		description = "Trojan:Win32/Crstase.RS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {33 c0 0f a2 89 45 fc 89 5d f8 89 4d ec 89 55 f0 b8 01 00 00 00 0f a2 } //01 00 
		$a_00_1 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //01 00  GetClipboardData
		$a_01_2 = {40 2e 72 65 70 33 31 } //00 00  @.rep31
	condition:
		any of ($a_*)
 
}