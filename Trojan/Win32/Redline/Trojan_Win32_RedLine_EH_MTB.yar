
rule Trojan_Win32_RedLine_EH_MTB{
	meta:
		description = "Trojan:Win32/RedLine.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {6b c0 16 99 bf 25 00 00 00 f7 ff 6b c0 2c 83 e0 2c 33 f0 03 ce 8b 55 0c 03 55 dc 88 0a } //00 00 
	condition:
		any of ($a_*)
 
}