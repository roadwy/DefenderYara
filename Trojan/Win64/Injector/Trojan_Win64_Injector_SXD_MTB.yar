
rule Trojan_Win64_Injector_SXD_MTB{
	meta:
		description = "Trojan:Win64/Injector.SXD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {44 32 d6 41 fe c2 c1 64 24 08 ?? 41 80 f2 86 48 c7 44 24 00 ?? ?? ?? ?? 41 d0 ca 48 c1 74 24 08 ?? 66 81 6c 24 01 ?? ?? 48 c1 4c 24 07 ?? 41 80 f2 32 48 ff 44 24 08 c1 7c 24 0b } //20
		$a_03_1 = {41 fe cb 41 32 f3 f7 5c 24 ?? 48 c1 4c 24 ?? ?? 4e 8d 5c 1c ?? 41 88 0b 0f 99 44 24 ?? 48 8d 64 24 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}