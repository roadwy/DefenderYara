
rule Ransom_Win32_Genasom_VIS_MSR{
	meta:
		description = "Ransom:Win32/Genasom.VIS!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 84 18 01 24 0a 00 8b 0d 90 01 04 88 04 19 90 00 } //01 00 
		$a_00_1 = {89 45 f8 33 45 e0 33 45 f0 2b d8 8b 45 d8 29 45 f4 ff 4d ec 0f 85 12 ff ff ff 8b 45 08 89 78 04 5f 5e 89 18 } //00 00 
	condition:
		any of ($a_*)
 
}