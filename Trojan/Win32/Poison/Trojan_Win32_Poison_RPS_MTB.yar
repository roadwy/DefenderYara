
rule Trojan_Win32_Poison_RPS_MTB{
	meta:
		description = "Trojan:Win32/Poison.RPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4d d0 83 c1 01 89 4d d0 83 7d d0 0d 73 17 8b 55 d0 33 c0 8a 44 15 e0 35 cc 00 00 00 8b 4d d0 88 44 0d e0 eb da } //00 00 
	condition:
		any of ($a_*)
 
}