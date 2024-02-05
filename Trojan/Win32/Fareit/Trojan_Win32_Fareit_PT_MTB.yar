
rule Trojan_Win32_Fareit_PT_MTB{
	meta:
		description = "Trojan:Win32/Fareit.PT!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 78 cb 9c 8b 78 cb 9c 8b 78 cb 9c 8b 78 cb 9c 8b 78 cb 9c 8b 78 cb 9c 8b 78 cb 9c 8b 78 cb 9c 8b 78 cb 9c 8b 78 bf 9c 8b 78 a2 9c 8b 78 5d } //00 00 
	condition:
		any of ($a_*)
 
}