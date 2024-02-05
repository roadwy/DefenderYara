
rule Virus_Win32_Expiro_CD{
	meta:
		description = "Virus:Win32/Expiro.CD,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {a1 d0 30 1b 01 03 05 90 30 1b 01 83 e8 09 } //01 00 
		$a_01_1 = {e8 32 df ff ff e8 4d 91 ff ff e8 88 11 00 00 e8 c9 91 ff ff 68 0f 01 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}