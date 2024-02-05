
rule Ransom_Win32_Thieflock_RIM_MTB{
	meta:
		description = "Ransom:Win32/Thieflock.RIM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 30 d0 32 d8 32 08 33 18 33 28 33 38 33 48 33 60 33 6c 33 70 33 74 33 90 33 94 33 b8 38 c8 38 cc 38 d0 38 d4 38 d8 38 dc 38 e0 38 e4 38 e8 38 ec 38 f8 38 fc 38 } //00 00 
	condition:
		any of ($a_*)
 
}