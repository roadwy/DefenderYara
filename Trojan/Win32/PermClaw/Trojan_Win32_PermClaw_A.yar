
rule Trojan_Win32_PermClaw_A{
	meta:
		description = "Trojan:Win32/PermClaw.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 03 45 fc 0f be ?? 0f b6 ?? ?? 33 ca } //1
		$a_03_1 = {89 51 30 b8 4d 4f 00 00 8b ?? f8 66 89 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}