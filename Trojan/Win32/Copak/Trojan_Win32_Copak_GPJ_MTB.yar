
rule Trojan_Win32_Copak_GPJ_MTB{
	meta:
		description = "Trojan:Win32/Copak.GPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {a2 ad 47 00 [0-08] 96 af 47 00 [0-30] 81 ?? ff 00 00 00 [0-20] 31 [0-30] 0f 8c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}