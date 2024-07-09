
rule Trojan_Win32_Pterodo_YAD_MTB{
	meta:
		description = "Trojan:Win32/Pterodo.YAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 08 8b 55 ?? 03 55 e0 0f b6 42 ff 33 c8 8b 55 ?? 03 55 e0 88 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}