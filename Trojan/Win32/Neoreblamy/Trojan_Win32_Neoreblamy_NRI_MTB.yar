
rule Trojan_Win32_Neoreblamy_NRI_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NRI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {7d 73 83 65 b8 00 eb 07 8b 45 b8 40 89 45 b8 } //1
		$a_01_1 = {7d 3b 8b 85 08 ff ff ff 8b 4d 90 d3 e0 8b 8d 40 ff ff ff 03 4d 88 23 c1 99 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}