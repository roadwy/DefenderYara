
rule Trojan_Win32_ICLoader_BO_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ec 08 a0 ?? ?? ?? 00 8a 0d ?? ?? ?? 00 32 c8 8b 15 ?? ?? ?? 00 88 0d ?? ?? ?? 00 8a 0d ?? ?? ?? 00 80 c9 0c 6a 01 c0 e9 02 81 e1 ff 00 00 00 52 89 4c 24 08 db 44 24 08 dc 3d } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}