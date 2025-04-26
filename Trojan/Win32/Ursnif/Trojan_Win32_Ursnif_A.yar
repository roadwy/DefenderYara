
rule Trojan_Win32_Ursnif_A{
	meta:
		description = "Trojan:Win32/Ursnif.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {0f b7 ce 03 ca 81 f9 9d 02 00 00 } //1
		$a_00_1 = {33 d2 8b c3 2b c6 05 bc 2b 00 00 } //1
		$a_02_2 = {81 c2 48 59 a3 01 8d 78 a7 89 0d ?? ?? ?? ?? 89 55 00 be 06 00 00 00 81 ff 38 1d 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}