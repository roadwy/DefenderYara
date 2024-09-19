
rule Trojan_Win32_CryptInject_PO_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.PO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e6 c1 ea ?? 8d 04 52 8d 04 41 8b ce 03 c3 8d 04 40 2b c8 8a 44 0c ?? 30 04 37 46 8b 4c 24 ?? 81 fe } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}