
rule Trojan_Win32_Crysan_AMMF_MTB{
	meta:
		description = "Trojan:Win32/Crysan.AMMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d0 33 ca 0f af 4d dc 89 8d ?? ?? ?? ?? 52 50 83 c4 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}