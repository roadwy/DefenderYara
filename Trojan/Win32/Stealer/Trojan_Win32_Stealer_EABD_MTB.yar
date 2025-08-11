
rule Trojan_Win32_Stealer_EABD_MTB{
	meta:
		description = "Trojan:Win32/Stealer.EABD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c7 03 c8 81 e1 ff 00 00 00 8b f9 8a 97 ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 88 96 ?? ?? ?? ?? 81 fe 39 0f 00 00 } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}