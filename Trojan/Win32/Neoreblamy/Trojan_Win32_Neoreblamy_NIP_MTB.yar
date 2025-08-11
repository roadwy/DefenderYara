
rule Trojan_Win32_Neoreblamy_NIP_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NIP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 d8 40 89 45 d8 83 7d d8 ?? 7d 10 8b 45 d8 } //1
		$a_03_1 = {6a 04 58 c1 e0 00 8b 84 05 ?? ?? ff ff 6a 04 59 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}