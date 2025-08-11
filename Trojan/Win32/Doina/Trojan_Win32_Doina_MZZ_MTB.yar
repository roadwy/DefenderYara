
rule Trojan_Win32_Doina_MZZ_MTB{
	meta:
		description = "Trojan:Win32/Doina.MZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c9 83 fa 2c 0f 45 cb 33 db 8a 84 0d ?? ?? ?? ?? 30 04 16 42 8d 41 01 89 95 30 ff ff ff 83 f8 14 0f 4c d8 8b c2 99 3b 95 28 ff ff ff 8b 95 30 ff ff ff 7c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}