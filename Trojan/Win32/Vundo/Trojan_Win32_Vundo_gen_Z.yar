
rule Trojan_Win32_Vundo_gen_Z{
	meta:
		description = "Trojan:Win32/Vundo.gen!Z,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 ff 35 30 00 00 00 58 c3 00 } //2
		$a_03_1 = {66 81 38 4d 5a c3 00 90 09 05 00 e8 ?? 00 00 00 } //1
		$a_03_2 = {66 81 38 4d 5a [0-03] c3 00 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}