
rule Trojan_Win64_CryptInject_SWK_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.SWK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f af c1 89 83 b4 00 00 00 8b 03 ff c8 01 43 14 8b 83 ?? ?? ?? ?? 8b 8b ?? ?? ?? ?? 81 e9 dd 0e 12 00 0f af c1 89 83 ?? ?? ?? ?? 8b 83 b4 00 00 00 33 43 40 83 f0 01 89 43 40 49 81 f9 00 9a 02 00 0f 8c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}