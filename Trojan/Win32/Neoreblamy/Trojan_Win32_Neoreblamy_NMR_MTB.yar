
rule Trojan_Win32_Neoreblamy_NMR_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 dc 40 89 45 dc 83 7d dc 01 7d 0d 8b 45 dc } //1
		$a_01_1 = {eb 07 83 a5 68 fd ff ff 00 6a 04 58 6b c0 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}