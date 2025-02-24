
rule Trojan_Win64_CryptInject_GTN_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.GTN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 09 c2 48 39 da 0f 82 ?? ?? ?? ?? 48 89 d9 e8 ?? ?? ?? ?? 48 8d 3d ?? ?? ?? ?? 48 8b 35 ?? ?? ?? ?? 49 bc } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}