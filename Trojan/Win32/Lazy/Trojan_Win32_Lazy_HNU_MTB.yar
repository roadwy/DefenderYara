
rule Trojan_Win32_Lazy_HNU_MTB{
	meta:
		description = "Trojan:Win32/Lazy.HNU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c4 60 c3 48 8d 05 68 6d 17 00 bb 21 00 00 00 e8 ec 37 02 00 90 48 89 44 24 08 48 89 5c 24 10 48 89 4c 24 18 48 89 7c 24 20 e8 d2 dc 04 00 48 8b 44 24 08 48 8b 5c 24 10 48 8b 4c 24 18 48 8b 7c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}