
rule Trojan_Win32_Fragtor_JZP_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.JZP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 c2 88 45 f3 8d 45 fc e8 f9 af f6 ff 8b 55 fc 8a 54 1a ff 80 e2 f0 8a 4d f3 02 d1 88 54 18 ff 46 8b 45 ?? e8 85 ad f6 ff 3b f0 7e } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}