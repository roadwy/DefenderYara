
rule Trojan_Win64_Lazy_PIN_MTB{
	meta:
		description = "Trojan:Win64/Lazy.PIN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 8b c9 48 2b c8 40 32 f9 49 8b c7 49 f7 e2 48 c1 ea 07 48 69 c2 ff 00 00 00 49 8b ca 48 2b ?? 40 32 f9 41 32 f8 42 30 7c 05 c8 49 ff c0 4d 03 cd 49 83 c2 06 4d 3b ce 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}