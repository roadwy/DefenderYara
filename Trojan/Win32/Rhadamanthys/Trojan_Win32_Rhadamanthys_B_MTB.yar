
rule Trojan_Win32_Rhadamanthys_B_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 f9 6b c0 ?? c1 e0 ?? 8b 55 0c 03 55 fc 0f b6 0a 33 c8 8b 55 0c 03 55 fc 88 0a eb } //2
		$a_03_1 = {f7 fe 8b 45 08 0f be 14 10 6b d2 ?? 81 e2 ?? ?? ?? ?? 33 ca 88 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}