
rule Trojan_Win32_Cutwail_ARA_MTB{
	meta:
		description = "Trojan:Win32/Cutwail.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 99 6a 37 5f f7 ff 8a 82 ?? ?? ?? ?? 8b 55 8c 32 04 11 88 04 31 41 3b 4d } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}