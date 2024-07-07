
rule Trojan_Win32_Lokibot_V_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_02_0 = {c6 03 e8 8d 56 90 01 01 8b c3 e8 90 01 04 89 43 01 8b 07 89 43 05 89 1f 83 c3 90 01 01 8b c3 2b c6 3d 90 01 04 7c 90 00 } //1
		$a_02_1 = {8b 55 08 03 d0 80 32 c1 40 3d 90 01 04 75 90 00 } //2
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*2) >=3
 
}