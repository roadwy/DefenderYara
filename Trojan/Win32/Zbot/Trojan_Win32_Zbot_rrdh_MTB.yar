
rule Trojan_Win32_Zbot_rrdh_MTB{
	meta:
		description = "Trojan:Win32/Zbot.rrdh!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {66 8b 06 8a e0 32 e1 8a c4 } //0a 00 
		$a_01_1 = {01 c3 ff 08 33 33 c0 ff 10 40 ff 10 10 cc c3 10 75 40 03 40 e8 33 01 75 10 } //00 00 
	condition:
		any of ($a_*)
 
}