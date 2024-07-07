
rule Trojan_Win64_WinGoObfusc_LK_MTB{
	meta:
		description = "Trojan:Win64/WinGoObfusc.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 0f b6 44 0c 77 44 0f b6 4c 0c 5e 45 29 c1 44 88 4c 0c 5e 48 ff c1 48 83 f9 19 7c e3 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}