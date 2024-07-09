
rule Trojan_Win64_Bumblebee_WIP_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.WIP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 ff c5 4c 8b 84 24 30 01 00 00 41 83 c4 02 44 0f b6 9c 24 20 01 00 00 41 83 c7 03 48 63 c8 48 63 05 ?? ?? ?? ?? 44 0f b7 cb 49 89 0c c6 8b c7 99 42 8d 0c 8d 00 00 00 00 f7 3d ?? ?? ?? ?? 0f b6 0c ce ff c7 32 c8 48 8b 44 24 78 00 0c 28 41 8d 49 24 ff 0d ?? ?? ?? ?? 48 63 ef 48 3b 2c ce 0f 83 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}