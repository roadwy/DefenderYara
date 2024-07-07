
rule Trojan_Win32_Citadel_MBHK_MTB{
	meta:
		description = "Trojan:Win32/Citadel.MBHK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4d 08 0f bf 11 33 c9 3b d0 0f 94 c1 f7 d9 8b f1 8d 4d 98 } //1
		$a_01_1 = {e0 44 40 00 ec 16 40 00 00 f0 30 00 00 ff ff ff 08 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}