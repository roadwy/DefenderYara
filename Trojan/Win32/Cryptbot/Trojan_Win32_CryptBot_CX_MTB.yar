
rule Trojan_Win32_CryptBot_CX_MTB{
	meta:
		description = "Trojan:Win32/CryptBot.CX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c8 40 3d ?? ?? ?? ?? 7c ?? 8b 45 08 32 ca 80 f1 ?? 88 0c 06 b9 ?? ?? ?? ?? 46 3b f7 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}