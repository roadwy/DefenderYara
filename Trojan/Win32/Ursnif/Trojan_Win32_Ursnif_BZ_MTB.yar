
rule Trojan_Win32_Ursnif_BZ_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b d3 c1 ca ?? 83 c4 ?? 03 d6 03 d0 03 fa 33 df } //2
		$a_03_1 = {8b d7 c1 ca ?? 03 d6 03 d0 8b 45 ?? 03 da 33 fb 89 7d } //2
		$a_03_2 = {8b c2 c1 e8 ?? 03 c2 6b c0 ?? 2b c8 8a b9 ?? ?? ?? ?? 32 fb } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=2
 
}