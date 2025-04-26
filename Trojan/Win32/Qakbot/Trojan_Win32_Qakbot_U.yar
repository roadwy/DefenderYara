
rule Trojan_Win32_Qakbot_U{
	meta:
		description = "Trojan:Win32/Qakbot.U,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_00_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {08 01 00 00 32 ?? ?? 04 88 ?? ?? ?? 3b ?? 72 e8 90 0a 1a 00 76 18 8b ?? 83 ?? 03 8a } //10
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*10) >=11
 
}