
rule Trojan_Win32_Xmrig_A_MTB{
	meta:
		description = "Trojan:Win32/Xmrig.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {f7 f9 8b 45 08 0f be 04 10 69 c0 } //02 00 
		$a_03_1 = {08 33 ca 8b 90 01 01 0c 03 90 01 01 dc 88 0a eb 90 09 08 00 8b 90 01 01 0c 03 90 01 01 dc 0f b6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}