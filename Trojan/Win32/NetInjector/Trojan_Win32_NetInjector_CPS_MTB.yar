
rule Trojan_Win32_NetInjector_CPS_MTB{
	meta:
		description = "Trojan:Win32/NetInjector.CPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 99 bf 90 01 04 f7 ff 8b 45 08 0f be 04 10 69 c0 89 0b 00 00 6b c0 90 01 01 99 83 e2 90 01 01 03 c2 c1 f8 90 01 01 6b c0 90 01 01 83 e0 90 01 01 33 f0 03 ce 8b 55 0c 03 55 fc 88 0a 0f be 45 fb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}