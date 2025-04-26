
rule Trojan_Win32_NSISInject_AJ_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {53 68 80 00 00 00 6a 03 53 6a 01 68 00 00 00 80 8d 85 [0-04] 50 ff 15 [0-04] 8b f0 53 56 ff 15 [0-04] 6a 40 68 00 30 00 00 8b d8 53 6a 00 ff 15 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}