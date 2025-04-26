
rule Trojan_Win32_Injector_YB_bit{
	meta:
		description = "Trojan:Win32/Injector.YB!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 03 85 ?? ?? ff ff 8a 00 32 84 95 f4 fb ff ff 8b 4d 08 03 8d ?? ?? ff ff 88 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}