
rule Trojan_Win32_Shelm_F_MTB{
	meta:
		description = "Trojan:Win32/Shelm.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 10 2b 45 f4 c7 44 24 0c 00 00 00 00 89 44 24 08 8b 45 f0 89 44 24 04 8b 45 08 89 04 24 a1 ?? ?? ?? ?? ff d0 83 ec 10 89 45 ec 8b 45 ec 01 45 f0 8b 45 ec 01 45 f4 83 7d ec ff } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}