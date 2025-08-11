
rule Trojan_Win32_Lazy_GY_MTB{
	meta:
		description = "Trojan:Win32/Lazy.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 1c 08 0f b7 d6 80 c3 20 32 5c 55 ?? 46 88 1c 08 41 3b 4d 0c } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}