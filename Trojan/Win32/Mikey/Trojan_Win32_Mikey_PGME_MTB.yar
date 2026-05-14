
rule Trojan_Win32_Mikey_PGME_MTB{
	meta:
		description = "Trojan:Win32/Mikey.PGME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 81 00 80 42 00 c0 c8 03 32 83 ?? ?? ?? ?? 88 81 00 80 42 00 8d 43 01 99 41 f7 fe 8b da 81 f9 ?? ?? ?? ?? 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}