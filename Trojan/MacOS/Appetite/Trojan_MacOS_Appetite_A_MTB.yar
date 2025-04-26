
rule Trojan_MacOS_Appetite_A_MTB{
	meta:
		description = "Trojan:MacOS/Appetite.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e8 5c 38 00 00 85 c0 0f 8e d7 01 00 00 f6 85 d0 fe ff ff 01 0f 84 00 01 00 00 31 ff 4c 89 ee ba 80 00 00 00 e8 2c 38 00 00 89 85 bc fe ff ff 85 c0 0f 8e 12 ff ff ff 48 8b 0d 9d 46 00 00 83 3d ea 45 00 00 00 74 71 48 85 c9 75 04 89 c2 eb 53 } //1
		$a_03_1 = {42 09 9c bd d0 fe ff ff 48 63 05 6d 46 00 00 48 85 c0 7e 2a 48 89 85 c0 fe ff ff c7 85 c8 fe ff ff 00 00 00 00 31 d2 bf 00 04 00 00 ?? ?? ?? ?? ?? ?? ?? 31 c9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}