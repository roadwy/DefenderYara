
rule Trojan_Win32_Sabsik_VBNV_MTB{
	meta:
		description = "Trojan:Win32/Sabsik.VBNV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 c6 48 c0 04 00 00 00 81 ef b3 7a 65 f8 39 f0 75 e7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}