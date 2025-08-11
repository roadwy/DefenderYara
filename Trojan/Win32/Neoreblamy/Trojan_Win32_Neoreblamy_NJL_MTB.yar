
rule Trojan_Win32_Neoreblamy_NJL_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NJL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 f4 48 89 45 f4 83 7d f4 ff } //1
		$a_03_1 = {7c c9 46 81 fe ?? ?? 00 00 7c be 81 7c 24 0c } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}