
rule Trojan_Win32_Qakbot_PY_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 3a e4 90 13 bb 08 00 00 00 53 3a db 90 13 5e f7 f6 66 3b c0 90 13 8b 45 ?? 0f b6 44 10 10 3a ff 90 13 33 c8 8b 45 ?? 3a e4 90 13 03 45 ?? 88 08 90 13 8b 45 ?? 40 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}