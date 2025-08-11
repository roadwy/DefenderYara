
rule Trojan_Win32_Neoreblamy_PGNE_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.PGNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 c7 84 85 ?? ?? ?? ?? ?? ?? ?? ?? ff 45 f8 39 4d f8 7c ea } //1
		$a_03_1 = {f7 d8 1b c0 40 2b 45 ?? f7 d8 1b c0 40 } //4
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*4) >=5
 
}