
rule Trojan_Win32_SnakeKeylogger_RPY_MTB{
	meta:
		description = "Trojan:Win32/SnakeKeylogger.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f6 d0 04 52 34 7f 2a c1 f6 d0 04 5e f6 d0 32 c1 c0 c0 02 f6 d8 88 81 ?? ?? ?? ?? 41 81 f9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}