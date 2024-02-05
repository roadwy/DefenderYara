
rule Trojan_Win32_StopCrypt_RPS_MTB{
	meta:
		description = "Trojan:Win32/StopCrypt.RPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {d3 e2 33 f6 89 74 24 28 03 54 24 48 8b 44 24 10 01 44 24 28 8b 44 24 18 01 44 24 28 8b 44 24 28 89 44 24 1c 8b 44 24 18 8b 4c 24 20 d3 e8 } //00 00 
	condition:
		any of ($a_*)
 
}