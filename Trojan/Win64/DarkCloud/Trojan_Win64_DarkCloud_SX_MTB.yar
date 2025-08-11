
rule Trojan_Win64_DarkCloud_SX_MTB{
	meta:
		description = "Trojan:Win64/DarkCloud.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {89 fd 21 dd 31 fb 44 89 cf 09 eb 89 d5 44 21 fd 41 31 d7 41 09 ef 89 da f7 d2 } //5
		$a_03_1 = {4c 89 84 24 80 00 00 00 4c 89 c6 48 21 fe 48 09 de 48 31 fe 48 89 f3 48 f7 d3 48 bf ?? ?? ?? ?? ?? ?? ?? ?? 48 21 fb 48 f7 d7 } //3
		$a_03_2 = {48 89 d9 31 d2 45 31 c0 45 31 c9 ff 15 ?? ?? ?? ?? 85 c0 b8 e5 ad 15 4e 41 0f 44 c6 3d 43 2e 7a 25 } //2
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*3+(#a_03_2  & 1)*2) >=10
 
}