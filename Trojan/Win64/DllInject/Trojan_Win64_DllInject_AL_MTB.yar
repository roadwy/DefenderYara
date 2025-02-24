
rule Trojan_Win64_DllInject_AL_MTB{
	meta:
		description = "Trojan:Win64/DllInject.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 8d 42 01 41 83 c2 04 48 63 c8 48 8b c3 48 f7 e1 48 c1 ea 04 48 6b c2 ?? 48 2b c8 49 0f af cf 0f b6 44 0c ?? 43 32 44 30 fc 41 88 40 ff 49 ff cc 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}