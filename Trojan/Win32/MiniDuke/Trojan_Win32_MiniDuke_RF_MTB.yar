
rule Trojan_Win32_MiniDuke_RF_MTB{
	meta:
		description = "Trojan:Win32/MiniDuke.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 e0 3f 83 c0 20 8b 8d f0 d3 ff ff 88 01 8b 85 90 e7 ff ff 0f be 00 25 c0 00 00 00 8b 8d f4 d3 ff ff d3 f8 0f b6 8d 9f e7 ff ff 0b c8 88 8d 9f e7 ff ff } //00 00 
	condition:
		any of ($a_*)
 
}