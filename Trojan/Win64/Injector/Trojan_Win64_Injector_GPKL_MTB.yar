
rule Trojan_Win64_Injector_GPKL_MTB{
	meta:
		description = "Trojan:Win64/Injector.GPKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c8 44 8b ca 0f 1f 40 00 6b c9 21 4d 8d 40 01 41 33 c9 45 0f be 48 ff 45 85 c9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}