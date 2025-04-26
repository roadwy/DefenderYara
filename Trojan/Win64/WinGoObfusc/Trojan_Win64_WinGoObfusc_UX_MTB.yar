
rule Trojan_Win64_WinGoObfusc_UX_MTB{
	meta:
		description = "Trojan:Win64/WinGoObfusc.UX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 07 48 ff c7 08 c0 74 d7 48 89 f9 48 89 fa ff c8 f2 ae 48 89 e9 ff 15 2e 01 00 00 48 09 c0 74 09 48 89 03 48 83 c3 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}