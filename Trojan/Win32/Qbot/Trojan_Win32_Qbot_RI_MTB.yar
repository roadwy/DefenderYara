
rule Trojan_Win32_Qbot_RI_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 86 d8 00 00 00 03 c1 89 46 7c b8 7d a4 15 00 2b 46 10 01 46 2c 8b 86 94 00 00 00 35 7c 8c 0f 00 29 86 a4 00 00 00 8b c2 0f af c2 01 86 f4 00 00 00 8b 86 fc 00 00 00 05 84 8f 02 00 03 46 48 31 86 b0 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}