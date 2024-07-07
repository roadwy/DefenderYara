
rule Trojan_Win32_Copak_MB_MTB{
	meta:
		description = "Trojan:Win32/Copak.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 c8 68 d8 85 40 00 5a e8 1e 00 00 00 31 13 81 e9 0b 3a 89 5d 43 01 c0 81 c0 01 00 00 00 39 f3 75 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}