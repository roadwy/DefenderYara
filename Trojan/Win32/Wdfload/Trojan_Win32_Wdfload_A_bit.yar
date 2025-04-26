
rule Trojan_Win32_Wdfload_A_bit{
	meta:
		description = "Trojan:Win32/Wdfload.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 08 8b 44 24 08 80 ?? ?? 8a [0-06] 32 c8 8b 44 24 08 88 [0-06] ff 44 24 08 83 7c 24 08 ?? 72 } //1
		$a_03_1 = {0f be 08 8d 52 01 ?? ?? 81 c6 ?? ?? ?? ?? 88 8d ?? ?? ?? ?? 8a 85 ?? ?? ?? ?? 30 42 ff 8b 85 ?? ?? ?? ?? 83 ef 01 75 d8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}