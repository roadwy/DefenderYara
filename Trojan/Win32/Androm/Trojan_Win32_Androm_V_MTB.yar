
rule Trojan_Win32_Androm_V_MTB{
	meta:
		description = "Trojan:Win32/Androm.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 45 e4 8b 4d 90 01 01 83 e1 90 01 01 0f be 04 08 8b 4d 90 01 01 0f b6 54 0d 90 01 01 31 c2 88 d3 88 5c 0d 90 01 01 8b 45 90 01 01 83 c0 90 01 01 89 45 90 01 01 e9 90 00 } //2
		$a_02_1 = {8b 45 e4 8b 4d 90 01 01 83 e1 90 01 01 0f be 04 08 8b 4d 90 01 01 0f b6 14 0d 90 01 04 31 c2 88 d3 88 1c 0d 90 01 04 8b 45 90 01 01 83 c0 90 01 01 89 45 90 01 01 e9 90 00 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=2
 
}