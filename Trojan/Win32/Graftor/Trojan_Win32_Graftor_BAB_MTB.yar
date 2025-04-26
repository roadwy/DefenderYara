
rule Trojan_Win32_Graftor_BAB_MTB{
	meta:
		description = "Trojan:Win32/Graftor.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {f6 d2 02 d0 80 f2 01 d0 c2 f6 d2 80 c2 7f 88 90 90 ?? ?? ?? ?? 40 3d 05 4e 00 00 72 de } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}