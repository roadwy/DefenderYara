
rule Trojan_Win64_CryptInject_KIK_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.KIK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 ca 01 4b ?? 41 8b 14 02 49 83 c2 ?? 8b 4b ?? 8b 43 ?? 81 f1 ?? ?? ?? ?? 0f af c1 48 63 4b ?? 89 43 ?? 8b 43 ?? 31 43 ?? 0f b6 c2 0f b6 53 ?? 0f af d0 48 8b 83 ?? ?? ?? ?? 88 14 01 ff 43 ?? 8b 4b ?? 44 8b 83 } //1
		$a_03_1 = {ff c8 01 83 ?? ?? ?? ?? 8b 43 ?? 2d ?? ?? ?? ?? 0f af d0 8b 83 ?? ?? ?? ?? 89 93 ?? ?? ?? ?? 8b 4b ?? 44 01 43 ?? 81 c1 ?? ?? ?? ?? 03 ca 0f af ca 8b 93 ?? ?? ?? ?? 2b c2 2d ?? ?? ?? ?? 31 43 ?? 89 8b ?? ?? ?? ?? 49 81 fa ?? ?? ?? ?? 0f 8c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}