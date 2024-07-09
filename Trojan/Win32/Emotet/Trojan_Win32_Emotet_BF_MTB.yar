
rule Trojan_Win32_Emotet_BF_MTB{
	meta:
		description = "Trojan:Win32/Emotet.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {33 c0 88 04 ?? 40 3d 03 84 01 00 7c } //1
		$a_00_1 = {b9 03 84 01 00 03 c3 99 f7 f9 8b da } //1
		$a_02_2 = {6a 40 6a 4d 6a 41 68 00 00 80 00 68 ?? ?? ?? ?? 68 [0-06] ff 15 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}