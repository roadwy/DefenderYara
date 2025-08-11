
rule Trojan_Win64_RShell_AHB_MTB{
	meta:
		description = "Trojan:Win64/RShell.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8d 3d 13 45 00 00 48 89 54 24 40 4c 89 44 24 38 48 8d 54 24 51 4c 89 44 24 30 45 31 c0 44 89 4c 24 28 45 31 c9 48 89 7c 24 48 c7 44 24 20 01 00 00 00 ff 15 } //3
		$a_03_1 = {c7 05 6c 45 00 00 68 00 00 00 c7 05 9e 45 00 00 01 01 00 00 48 89 05 bb 45 00 00 48 89 05 ac 45 00 00 48 89 05 9d 45 00 00 48 b8 ?? ?? ?? ?? ?? ?? ?? 00 48 89 44 24 51 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}