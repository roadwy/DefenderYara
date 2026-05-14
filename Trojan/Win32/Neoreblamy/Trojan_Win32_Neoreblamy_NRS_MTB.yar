
rule Trojan_Win32_Neoreblamy_NRS_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NRS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {7d 5e 83 65 c4 00 eb 07 8b 45 c4 40 89 45 c4 } //1
		$a_03_1 = {6a 0c 58 6b c0 00 8d 84 05 ?? ?? ff ff 6a 04 59 d1 e1 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}