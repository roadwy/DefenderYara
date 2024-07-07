
rule Trojan_Win32_NSISInject_AK_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 80 00 00 00 6a 03 6a 00 6a 01 89 45 b0 8b 45 10 68 00 00 00 80 50 ff 15 90 02 04 8b f0 6a 00 56 ff 15 90 02 04 6a 40 8b d8 68 00 30 00 00 53 6a 00 89 5d ac ff 15 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}