
rule Trojan_Win32_Promete_YAA_MTB{
	meta:
		description = "Trojan:Win32/Promete.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {6d c6 80 42 75 9f 00 73 c6 80 ?? ?? ?? ?? 68 c6 80 ?? ?? ?? ?? 6c c6 80 ?? ?? ?? ?? 70 c6 80 ?? ?? ?? ?? 64 c6 80 ?? ?? ?? ?? 61 53 c6 80 48 75 9f 00 33 68 } //1
		$a_01_1 = {8a 4d fc 02 c8 30 0f 3b c3 } //10
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*10) >=11
 
}