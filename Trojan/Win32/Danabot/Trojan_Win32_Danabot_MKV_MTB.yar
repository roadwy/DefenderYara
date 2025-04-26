
rule Trojan_Win32_Danabot_MKV_MTB{
	meta:
		description = "Trojan:Win32/Danabot.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4a c1 e2 02 8b 1c 50 8b 45 f4 e8 ?? ?? ?? ?? 8b 55 f0 c1 e2 02 31 1c 50 ff 45 f0 ff 4d e4 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}