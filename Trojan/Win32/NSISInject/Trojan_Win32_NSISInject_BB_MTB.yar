
rule Trojan_Win32_NSISInject_BB_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 0c 6a 40 68 00 30 00 00 53 57 ff 15 [0-04] 56 6a 01 8b f8 53 57 e8 [0-04] 83 c4 10 33 c9 85 db 74 16 8b c1 99 6a 0c 5e f7 fe 8a 82 [0-04] 30 04 0f 41 3b cb 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}