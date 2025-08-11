
rule Trojan_Win32_Neoreblamy_NFT_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NFT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 dc 40 89 45 dc 83 7d dc 04 7d 10 8b 45 dc } //1
		$a_03_1 = {33 c0 40 6b c0 00 0f b6 84 05 ?? ?? ff ff 8d 44 00 02 39 45 b4 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}