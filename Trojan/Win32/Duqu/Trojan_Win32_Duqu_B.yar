
rule Trojan_Win32_Duqu_B{
	meta:
		description = "Trojan:Win32/Duqu.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {56 ff 75 0c 51 56 8d 4d ?? 51 57 ff d0 85 c0 74 0d 6a 01 68 ?? ?? 00 00 ff 15 ?? ?? ?? ?? 57 ff 15 } //1
		$a_03_1 = {83 c4 0c 8b 45 0c 0f b7 40 06 ff 45 f8 83 45 fc 28 83 c6 28 39 45 f8 7c ?? 8b c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}