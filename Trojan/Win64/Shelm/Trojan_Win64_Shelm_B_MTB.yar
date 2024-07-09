
rule Trojan_Win64_Shelm_B_MTB{
	meta:
		description = "Trojan:Win64/Shelm.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 83 ec 28 48 8d 0d e5 11 00 00 e8 90 } //2
		$a_03_1 = {ff 33 c9 ba ?? ?? ?? ?? 41 b8 00 10 00 00 44 8d 49 40 ff 15 69 0f 00 00 48 8d 0d ?? ?? ?? ?? 41 b8 ?? ?? ?? ?? 4c 8b c8 48 8b d0 66 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}