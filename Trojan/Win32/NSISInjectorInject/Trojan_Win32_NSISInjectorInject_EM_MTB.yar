
rule Trojan_Win32_NSISInjectorInject_EM_MTB{
	meta:
		description = "Trojan:Win32/NSISInjectorInject.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 16 16 7a 00 00 00 0d 00 00 00 21 00 00 00 43 5d 5d 5d ea 8f 8f 8f fa 9b 9b 9b fb 9c 9c 9c fc 9a 9a 9a fb b0 b0 b0 fb b1 b1 b1 fe 1a 1a 1a ff 17 17 17 ff 1b 1b 1b ff 1e 1e 1e ff 2d 2d 2d ff 41 41 41 ff 4d 4d 4d ff 4f 4f 4f ff 50 50 50 ff 50 50 50 ff 51 51 51 ff } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}