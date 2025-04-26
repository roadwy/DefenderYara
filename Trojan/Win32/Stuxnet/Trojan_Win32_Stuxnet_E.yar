
rule Trojan_Win32_Stuxnet_E{
	meta:
		description = "Trojan:Win32/Stuxnet.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {b2 00 eb 14 b2 01 eb 10 b2 02 eb 0c b2 03 eb 08 b2 04 eb 04 b2 05 eb 00 52 e8 04 00 00 00 ?? ?? ?? ?? 5a ff 22 e8 13 00 00 00 } //1
		$a_01_1 = {5a 84 d2 74 25 fe ca 0f 84 82 00 00 00 fe ca 0f 84 bb 00 00 00 fe ca 0f 84 fe 00 00 00 fe ca 0f 84 40 01 00 00 } //1
		$a_01_2 = {3d 02 06 24 ae 74 07 33 c0 e9 } //-10
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*-10) >=2
 
}