
rule Trojan_Win64_Marte_AMBE_MTB{
	meta:
		description = "Trojan:Win64/Marte.AMBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {4c 8d 4c 24 ?? ba ?? ?? ?? ?? 41 b8 20 00 00 00 48 8b cb ff 15 ?? ?? ?? ?? 85 c0 74 ?? 48 c7 44 24 28 ?? ?? ?? ?? 45 33 c9 4c 8b c3 c7 44 24 20 ?? ?? ?? ?? 33 d2 33 c9 ff 15 ?? ?? ?? ?? 48 8b c8 ba ?? ?? ?? ?? ff 15 } //2
		$a_01_1 = {43 72 65 61 74 65 54 68 72 65 61 64 } //1 CreateThread
		$a_01_2 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //1 WaitForSingleObject
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}