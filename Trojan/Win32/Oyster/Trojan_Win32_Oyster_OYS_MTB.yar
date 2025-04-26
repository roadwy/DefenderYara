
rule Trojan_Win32_Oyster_OYS_MTB{
	meta:
		description = "Trojan:Win32/Oyster.OYS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {50 6a 54 57 c7 45 a0 ?? ?? ?? ?? ff d6 85 c0 0f 84 ?? ?? ?? ?? 85 ff 0f 84 ?? ?? ?? ?? 83 7d 98 08 8d 45 84 6a 00 ff 75 10 0f 43 45 84 50 57 ff 15 } //2
		$a_01_1 = {4c 6f 61 64 65 72 5c 43 6c 65 61 6e 55 70 5c 52 65 6c 65 61 73 65 5c 43 6c 65 61 6e 55 70 2e 70 64 62 } //1 Loader\CleanUp\Release\CleanUp.pdb
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}