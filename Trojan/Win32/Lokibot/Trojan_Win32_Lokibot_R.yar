
rule Trojan_Win32_Lokibot_R{
	meta:
		description = "Trojan:Win32/Lokibot.R,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 08 80 f1 ?? 88 0b 42 40 81 fa 7c 5c 00 00 75 ca } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}