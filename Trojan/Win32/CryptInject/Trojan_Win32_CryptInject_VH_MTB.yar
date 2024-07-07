
rule Trojan_Win32_CryptInject_VH_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.VH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 f7 75 90 01 01 8a 44 15 90 01 01 32 84 31 90 01 04 88 04 1e 46 81 fe 90 01 04 72 db 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}