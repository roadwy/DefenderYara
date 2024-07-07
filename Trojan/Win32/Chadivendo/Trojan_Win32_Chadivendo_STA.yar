
rule Trojan_Win32_Chadivendo_STA{
	meta:
		description = "Trojan:Win32/Chadivendo.STA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 00 04 00 00 6a 00 6a 00 6a 06 90 02 0a ff 15 90 01 04 85 c0 90 02 06 c7 00 90 01 04 c7 40 04 90 01 04 ff 15 90 00 } //1
		$a_01_1 = {c7 00 49 1f 20 03 c7 40 04 99 df c1 18 ff 15 } //1
		$a_00_2 = {80 4f 00 00 00 5f ff ff ff ff 47 6c 6f 62 61 6c 5c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}