
rule Trojan_Win32_Phorpiex_RA_MTB{
	meta:
		description = "Trojan:Win32/Phorpiex.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 b9 ff 7f 00 00 f7 f9 81 c2 e8 03 00 00 52 e8 ?? ?? ?? ?? 99 b9 ff 7f 00 00 f7 f9 81 c2 e8 03 00 00 52 8d 95 ?? ?? ff ff 52 68 ?? ?? ?? ?? 8d 85 ?? ?? ff ff 50 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}