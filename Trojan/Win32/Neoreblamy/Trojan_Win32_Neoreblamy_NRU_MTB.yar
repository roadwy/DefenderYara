
rule Trojan_Win32_Neoreblamy_NRU_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NRU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {7d 46 83 65 a8 00 eb 07 8b 45 a8 40 89 45 a8 } //1
		$a_03_1 = {6b c0 05 8d 84 05 ?? ?? ff ff 6a 04 59 6b c9 06 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}