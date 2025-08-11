
rule Trojan_Win32_Zusy_BAE_MTB{
	meta:
		description = "Trojan:Win32/Zusy.BAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d 8c 8a 44 15 98 30 04 0f 47 81 ff ?? ?? ?? ?? 7c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}