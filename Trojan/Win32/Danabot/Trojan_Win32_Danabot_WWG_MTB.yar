
rule Trojan_Win32_Danabot_WWG_MTB{
	meta:
		description = "Trojan:Win32/Danabot.WWG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 8a 88 00 00 00 03 0d ?? ?? ?? ?? 03 c1 a3 ?? ?? ?? ?? 8b 86 ec 00 00 00 2b 86 e4 00 00 00 05 ec d9 12 00 01 82 98 00 00 00 a1 ?? ?? ?? ?? 8b 4e 48 88 1c 08 ff 46 48 8b 46 10 8b 5e 64 48 31 86 a0 00 00 00 8d 43 af 01 46 70 81 fd 68 fb 38 00 0f 8c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}