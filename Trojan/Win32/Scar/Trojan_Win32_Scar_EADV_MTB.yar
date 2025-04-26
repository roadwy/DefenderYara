
rule Trojan_Win32_Scar_EADV_MTB{
	meta:
		description = "Trojan:Win32/Scar.EADV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 45 fe 8b 4d 08 03 4d f0 0f b6 11 33 d0 8b 45 08 03 45 f0 88 10 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}