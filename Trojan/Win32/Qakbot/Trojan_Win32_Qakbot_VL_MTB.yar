
rule Trojan_Win32_Qakbot_VL_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.VL!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {2b 46 0c 01 86 28 01 00 00 8b 86 24 01 00 00 35 9d 88 f2 ff c1 ea 08 01 86 2c 01 00 00 8b 86 b8 00 00 00 88 14 01 } //00 00 
	condition:
		any of ($a_*)
 
}