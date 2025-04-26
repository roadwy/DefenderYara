
rule Trojan_Win32_Zlob_AK{
	meta:
		description = "Trojan:Win32/Zlob.AK,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 0f be 0c 18 66 83 e9 41 0f b7 c9 c1 e7 04 03 f9 83 c0 01 83 f8 04 0f b7 ff 72 e4 83 ca ff 2b 56 14 83 fa 01 77 05 e8 ?? ?? ?? 00 8b 6e 14 83 c5 01 81 fd fe ff ff 7f 76 05 e8 ?? ?? ?? 00 [0-20] 76 56 8b 56 14 81 f7 ?? ?? ?? ?? 0f b7 cf bf 08 00 00 00 39 7e 18 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}