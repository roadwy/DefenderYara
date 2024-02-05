
rule Trojan_Win32_TrickBotCrypt_MS_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {d3 c0 8a fc 8a e6 d3 cb ff 4d fc 75 90 02 18 31 90 02 03 8b 90 02 02 aa 49 75 90 00 } //01 00 
		$a_02_1 = {d3 c0 8a fc 8a e6 d3 cb ff 4d fc 75 90 02 18 33 90 02 05 8b 90 02 02 aa 49 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}