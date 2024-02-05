
rule Trojan_Win32_Zbot_BN_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {83 c0 02 bb b3 31 41 00 fe 03 43 81 fb c1 33 41 00 75 f5 b8 0b 00 00 00 47 81 ff 69 9c 01 00 75 } //00 00 
	condition:
		any of ($a_*)
 
}