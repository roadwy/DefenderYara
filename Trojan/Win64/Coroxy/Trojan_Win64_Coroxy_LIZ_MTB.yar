
rule Trojan_Win64_Coroxy_LIZ_MTB{
	meta:
		description = "Trojan:Win64/Coroxy.LIZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 d0 0f b6 85 a5 0a 00 00 0f af c2 ba 35 01 00 00 88 85 a5 0a 00 00 41 8b 41 ec 03 c1 ff c1 41 31 41 ?? 0f b7 05 bf ea 00 00 2b d0 8b c2 99 f7 3d ?? ?? 00 00 89 05 22 eb 00 00 81 f9 a3 0a 00 00 7f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}