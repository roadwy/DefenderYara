
rule Trojan_Win32_Neoreblamy_NME_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 c0 40 6b c0 00 0f b6 84 05 ?? ?? ff ff 8d 44 00 02 39 45 dc } //1
		$a_01_1 = {7d 70 83 65 9c 00 eb 07 8b 45 9c 40 89 45 9c 81 7d 9c } //2
		$a_01_2 = {eb 07 8b 45 8c 40 89 45 8c 83 7d 8c 03 7d 10 8b 45 8c } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=5
 
}