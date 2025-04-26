
rule Trojan_Win32_Amadey_CAJ_MTB{
	meta:
		description = "Trojan:Win32/Amadey.CAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 04 85 e8 a2 43 00 32 04 31 8b 4d ec 88 86 ?? ?? ?? ?? 46 3b 75 e4 7c ?? 81 fe ?? ?? ?? ?? 0f } //5
		$a_01_1 = {44 3a 5c 4d 6b 74 6d 70 5c 41 6d 61 64 65 79 5c 52 65 6c 65 61 73 65 5c 41 6d 61 64 65 79 2e 70 64 62 } //1 D:\Mktmp\Amadey\Release\Amadey.pdb
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}