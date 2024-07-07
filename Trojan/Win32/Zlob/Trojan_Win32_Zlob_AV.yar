
rule Trojan_Win32_Zlob_AV{
	meta:
		description = "Trojan:Win32/Zlob.AV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {76 50 8b 56 14 81 f5 90 01 04 0f b7 cd bd 08 00 00 00 39 6e 18 72 20 8b 03 eb 1e 85 ff 75 e0 90 00 } //1
		$a_01_1 = {6a 00 8d 54 24 18 52 6a 04 8d 44 24 1c 50 57 ff d3 85 c0 74 17 83 7c 24 14 04 75 10 8b 4c 24 10 89 4c b5 00 83 c6 01 83 fe 04 7c d4 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}