
rule Trojan_Win32_Scar_EAHH_MTB{
	meta:
		description = "Trojan:Win32/Scar.EAHH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 75 10 8b 45 0c 0f b6 14 10 03 ca 8b c1 99 b9 64 00 00 00 f7 f9 89 55 f4 8b 55 08 03 55 f8 8a 02 88 45 ff } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}