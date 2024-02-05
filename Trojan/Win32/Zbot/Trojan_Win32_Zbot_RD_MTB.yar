
rule Trojan_Win32_Zbot_RD_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 10 8a ca 80 e9 61 88 55 ff 80 f9 19 77 04 80 45 ff e0 8a 0c 06 8d 59 9f 80 fb 19 77 03 80 c1 e0 } //00 00 
	condition:
		any of ($a_*)
 
}