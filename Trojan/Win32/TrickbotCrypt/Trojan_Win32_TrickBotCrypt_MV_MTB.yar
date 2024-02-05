
rule Trojan_Win32_TrickBotCrypt_MV_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.MV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 06 46 85 c0 74 48 56 83 90 02 03 09 90 02 02 55 c7 90 02 06 59 bb 90 02 04 50 83 e0 00 09 f0 83 e2 00 09 c2 58 c7 45 90 02 05 d3 c0 8a fc 8a e6 d3 cb ff 4d fc 75 f3 8f 45 f4 8b 4d f4 89 75 f4 31 f6 09 de 89 f0 8b 75 f4 aa 49 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}