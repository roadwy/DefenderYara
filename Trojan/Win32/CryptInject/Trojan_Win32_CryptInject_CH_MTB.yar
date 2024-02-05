
rule Trojan_Win32_CryptInject_CH_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.CH!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {39 f6 74 01 ea 31 31 81 c1 04 00 00 00 39 c1 75 ef } //01 00 
		$a_01_1 = {81 c3 65 6e 08 a9 42 bf 3d 20 28 14 81 fa 42 4c 00 01 75 af } //00 00 
	condition:
		any of ($a_*)
 
}