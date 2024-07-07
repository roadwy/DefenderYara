
rule Trojan_Win32_Zenpack_MKW_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.MKW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 fe 81 e6 90 01 04 8b 7d 90 01 01 8a 1c 0f 8b 7d 90 01 01 32 1c 37 8b 75 90 01 01 88 1c 0e 81 c1 90 01 04 8b 75 90 01 01 39 f1 8b 75 90 01 01 89 4d 90 01 01 89 75 90 01 01 89 55 90 01 01 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}