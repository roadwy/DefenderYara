
rule Trojan_Win32_NSISInject_BN_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 42 01 99 f7 ff 0f b6 41 fe c0 c8 03 32 82 [0-04] 88 41 fe 8d 42 01 99 f7 ff 4e 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}