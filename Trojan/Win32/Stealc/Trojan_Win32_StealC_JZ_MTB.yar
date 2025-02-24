
rule Trojan_Win32_StealC_JZ_MTB{
	meta:
		description = "Trojan:Win32/StealC.JZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 44 24 0c 83 6c 24 ?? ?? 0f be 04 1f 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8a 4c 24 ?? 88 0c 1f 47 3b fd 7c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}